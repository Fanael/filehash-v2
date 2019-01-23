// Copyright 2019 Fanael Linithien
//
// This file is part of filehash-v2.
//
// filehash-v2 is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// filehash-v2 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with filehash-v2.  If not, see <https://www.gnu.org/licenses/>.
#include <array>
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>
#include <string.h>
#include <time.h>
#include "arg-parse.hh"
#include "blake2sp4.hh"
#include "database.hh"
#include "hash-engine.hh"
#include "main.hh"
#include "span.hh"
#include "sqlite.hh"
#include "syscall-error.hh"
#include "syscall-utils.hh"

namespace filehash {
namespace {

class time_error final : public syscall_error {
public:
    using syscall_error::syscall_error;
    const char* what() const noexcept override;
};

const char* time_error::what() const noexcept
{
    return "time error";
}

struct timestamp_formatter {
    time_t ts;
};

std::ostream& operator<<(std::ostream& stream, timestamp_formatter formatter)
{
    struct tm local_time;
    if(localtime_r(&formatter.ts, &local_time) == nullptr) {
        throw_errno<time_error>();
    }
    std::array<char, 500> buffer;
    const auto string_length = strftime(buffer.data(), buffer.size(), "%Y-%m-%d %H:%M:%S",
        &local_time);
    return stream << std::string_view(buffer.data(), string_length);
}


struct hex_byte_formatter {
    span<const std::byte> bytes;
};

std::ostream& operator<<(std::ostream& stream, hex_byte_formatter formatter)
{
    static constexpr char hex_digits[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    static_assert(CHAR_BIT == 8);
    for(const std::byte byte: formatter.bytes) {
        stream.put(hex_digits[static_cast<unsigned>(byte >> 4)]);
        stream.put(hex_digits[static_cast<unsigned>(byte & std::byte{0x0F})]);
    }
    return stream;
}


struct shared_state {
    bool verbose;
    std::mutex* output_mutex;
    std::mutex* input_mutex;
    std::ostream* verbose_output;
    std::ostream* error_output;
    // It's only used as a counter, it doesn't protect anything, so relaxed
    // operations are fine.
    mutable std::atomic<std::uint_least64_t> file_error_count;
};

void get_file_name(std::string& destination, const shared_state& shared)
{
    destination.clear();
    const std::lock_guard guard(*shared.input_mutex);
    std::getline(std::cin, destination, '\0');
}

void hashing_worker(db::hash_inserter& inserter, const shared_state& shared)
{
    hash_engine engine(inserter, *shared.output_mutex,
        shared.verbose ? shared.verbose_output : nullptr, *shared.error_output);
    std::string file_name;
    for(;;) {
        get_file_name(file_name, shared);
        if(file_name.empty()) {
            break;
        }
        try {
            engine.hash_file(file_name);
        } catch(const not_regular_file_error&) {
            const std::lock_guard guard(*shared.output_mutex);
            *shared.error_output << '"' << file_name << "\" is not a regular file, skipping\n"
                << std::flush;
        } catch(const syscall_error& e) {
            shared.file_error_count.fetch_add(1, std::memory_order_relaxed);
            const std::lock_guard guard(*shared.output_mutex);
            *shared.error_output << "Error processing file \"" << file_name << "\": " << e.what()
                << ": " << strerror(e.code()) << '\n' << std::flush;
        }
    }
}

std::size_t get_thread_count(std::size_t requested_count) noexcept
{
    if(requested_count > 0) {
        return requested_count;
    }
    const auto hardware_concurrency = std::thread::hardware_concurrency();
    if(hardware_concurrency > 0) {
        return 2 * hardware_concurrency;
    }
    return 2;
}

// std::future<void> and std::async would do the same thing, but they bloat
// the binary too much.
class worker {
public:
    template <typename F, typename = std::enable_if_t<!std::is_same_v<worker, std::decay_t<F>>>>
    explicit worker(F&& function);

    void join();
private:
    // Allocate it separately so that its address is stable.
    std::unique_ptr<std::exception_ptr> exception_ptr;
    std::thread thread;
};

template <typename F, typename>
worker::worker(F&& function)
    : exception_ptr(std::make_unique<std::exception_ptr>()),
      thread([excptr = exception_ptr.get(), func = std::forward<F>(function)]() mutable {
          try {
              func();
          } catch(...) {
              *excptr = std::current_exception();
          }
      })
{
}

void worker::join()
{
    thread.join();
    if(*exception_ptr != nullptr) {
        std::rethrow_exception(*exception_ptr);
    }
}

exit_status run_hashing_workers(db::snapshot& snapshot, const args::common_args& common_args)
{
    const auto worker_count = get_thread_count(common_args.thread_count);
    // Let every worker have their own inserter that stores data in a separate
    // temporary table.
    std::vector<db::hash_inserter> inserters;
    inserters.reserve(worker_count);
    for(std::size_t i = 0; i < worker_count; ++i) {
        inserters.push_back(snapshot.start_update(i));
    }

    std::mutex output_mutex;
    std::mutex input_mutex;
    const shared_state shared = {common_args.verbose, &output_mutex, &input_mutex, &std::cout,
        &std::clog, 0};
    std::vector<worker> workers;
    workers.reserve(worker_count);
    for(std::size_t i = 0; i < worker_count; ++i) {
        auto& our_inserter = inserters[i];
        workers.push_back(worker([&]{ hashing_worker(our_inserter, shared); }));
    }
    // Let all workers run to completion before saving their changes, to
    // hopefully reduce the database contention a bit.
    for(auto& worker: workers) {
        worker.join();
    }

    snapshot.update_end_time();
    for(auto& inserter: inserters) {
        inserter.merge_changes();
    }
    const auto file_error_count = shared.file_error_count.load(std::memory_order_relaxed);
    if(file_error_count > 0) {
        *shared.error_output << "Warning: " << file_error_count << " files failed to process.\n";
        return exit_status::harmless_error;
    }
    return exit_status::success;
}


exit_status run_command(const args::diff_command& args, const args::common_args&)
{
    db::database database(args.database_path);
    auto diff = database.open_diff(args.old_snapshot_name, args.new_snapshot_name);

    const auto stats = diff.get_file_counts();
    std::cout << "Files not changed: " << stats.equal_files << "\nFiles changed: "
        << stats.modified_files << "\nNew files: " << stats.new_files << "\nFiles removed: "
        << stats.deleted_files << '\n' << std::flush;

    bool found_mismatches = false;
    db::mismatched_files_cursor file_cursor(diff);
    db::mismatched_chunks_cursor chunks_cursor(diff);
    while(auto file = file_cursor.next()) {
        found_mismatches = true;
        std::clog << "Mismatch detected for \"" << file->file_path << "\"!\n Modification time: "
            << timestamp_formatter{file->modification_time.tv_sec} << '.' << std::setw(9)
            << std::setfill('0') << file->modification_time.tv_nsec << "\n Old hash: "
            << hex_byte_formatter{file->old_hash} << "\n New hash: "
            << hex_byte_formatter{file->new_hash} << '\n' << std::flush;

        chunks_cursor.rewind_to_file(file->file_id);
        while(auto chunk = chunks_cursor.next()) {
            const auto chunk_id = chunk->chunk_id;
            static_assert(chunk_size == 1048576, "chunk size differs from UI text");
            std::clog << "  Megabyte block #" << chunk->chunk_id
                << " mismatch (byte range " << chunk_id * int{chunk_size}
                << ".." << (chunk_id + 1) * int{chunk_size} - 1 << "):\n   Old block hash: "
                << hex_byte_formatter{chunk->old_hash} << "\n   New block hash: "
                << hex_byte_formatter{chunk->new_hash} << '\n' << std::flush;
        }
        std::clog << '\n';
    }

    return found_mismatches ? exit_status::mismatch_found : exit_status::success;
}

exit_status run_command(const args::gc_command& args, const args::common_args&)
{
    db::database database(args.database_path);
    database.vacuum();
    return exit_status::success;
}

exit_status run_command(const args::help_command& args, const args::common_args&)
{
    std::cout << args::usage(args.cookie, "filehash") << '\n';
    return exit_status::success;
}

exit_status run_command(const args::init_command& args, const args::common_args&)
{
    db::database::initialize(args.database_path);
    return exit_status::success;
}

exit_status run_command(const args::list_command& args, const args::common_args&)
{
    constexpr int name_width = 40;
    constexpr int timestamp_width = 22;

    db::database database(args.database_path);

    std::cout << std::setw(name_width) << "Snapshot name"
        << std::setw(timestamp_width) << "Creation time"
        << std::setw(timestamp_width) << "Last update time" << '\n';
    for(db::snapshot_cursor cursor(database); auto snapshot = cursor.next(); ) {
        std::cout << std::setw(name_width) << snapshot->name
            << std::setw(timestamp_width) << timestamp_formatter{snapshot->start_time.tv_sec}
            << std::setw(timestamp_width) << timestamp_formatter{snapshot->end_time.tv_sec}
            << '\n';
    }
    return exit_status::success;
}

exit_status run_command(const args::new_command& args, const args::common_args& common_args)
{
    db::database database(args.database_path);
    auto snapshot = database.create_empty_snapshot(args.snapshot_name);
    const auto status = run_hashing_workers(snapshot, common_args);
    database.save_changes();
    return status;
}

exit_status run_command(const args::new_empty_command& args, const args::common_args&)
{
    db::database database(args.database_path);
    database.create_empty_snapshot(args.snapshot_name);
    database.save_changes();
    return exit_status::success;
}

exit_status run_command(const args::remove_command& args, const args::common_args&)
{
    db::database database(args.database_path);
    if(!database.remove_snapshot(args.snapshot_name)) {
        std::clog << "Snapshot named " << args.snapshot_name << " not found, nothing removed.\n";
        return exit_status::harmless_error;
    }
    database.save_changes();
    return exit_status::success;
}

exit_status run_command(const args::update_command& args, const args::common_args& common_args)
{
    db::database database(args.database_path);
    auto snapshot = database.open_snapshot(args.snapshot_name);
    const auto status = run_hashing_workers(snapshot, common_args);
    database.save_changes();
    return status;
}

exit_status main(span<const std::string_view> args)
{
    try {
        auto parsed_args = args::parse_args(args);
        return std::visit([&](const auto& cmd) { return run_command(cmd, parsed_args.common); },
            parsed_args.cmd);
    } catch(const args::parse_error& e) {
        std::clog << e << "\n\n" << args::usage(e.command(), args.front()) << '\n';
        return exit_status::usage;
    } catch(const syscall_error& e) {
        std::clog << "System error: " << e.what() << ": " << strerror(e.code()) << '\n';
        return exit_status::error;
    } catch(const db::error& e) {
        std::clog << "Database error: " << e.what() << '\n';
        return exit_status::error;
    } catch(const sqlite::error& e) {
        std::clog << "SQLite error: " << e.what() << '\n';
        return exit_status::error;
    } catch(const std::exception& e) {
        std::clog << "Internal error: " << e.what() << '\n';
        return exit_status::error;
    }
}

} // unnamed namespace
} // namespace filehash

int main(int argc, char** argv)
{
    std::ios_base::sync_with_stdio(false);
    // We use std::cin as the file name source, so it doesn't make sense for it
    // to be tied to std::cout.
    std::cin.tie(nullptr);
    std::clog.tie(&std::cout);
    tzset();

    std::vector<std::string_view> args(argv, argv + argc);
    return static_cast<int>(filehash::main(args));
}
