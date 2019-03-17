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
#include <cstddef>
#include <mutex>
#include <ostream>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include "database.hh"
#include "file-descriptor.hh"
#include "hash-engine.hh"
#include "span.hh"
#include "syscall-utils.hh"

namespace filehash {
namespace {

constexpr std::size_t buffer_size = 16384;

static_assert(buffer_size <= chunk_size);

class concurrent_modification_error final : public std::exception {};

} // unnamed namespace

hash_engine::hash_engine(db::hash_inserter& inserter, std::mutex& output_mutex,
    std::ostream* verbose_output, std::ostream& error_output,
    const file_watcher_factory& watcher_factory)
    : buffer(new std::byte[buffer_size]),
      inserter(&inserter),
      watcher(watcher_factory()),
      space_left_in_chunk(chunk_size),
      chunk_id(0),
      file_id(0),
      output_mutex(&output_mutex),
      error_output(&error_output),
      verbose_output(verbose_output)
{
}

void hash_engine::hash_file(const std::string& file_name)
{
    // NB: O_NONBLOCK so that open does not block on FIFOs.
    file_descriptor file(wrap_syscall<file_error>([&]{
        return open(file_name.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    }));
    if(!S_ISREG(file.stat().st_mode)) {
        throw not_regular_file_error();
    }
    // O_NONBLOCK has no effect on regular files on existing systems, but the
    // manpage says it might change in the future, so drop it before actually
    // doing something with the file.
    file.drop_o_nonblock();
    file.fadvise(POSIX_FADV_SEQUENTIAL);
    if(verbose_output != nullptr) {
        const std::lock_guard guard(*output_mutex);
        *verbose_output << "Hashing file \"" << file_name << "\"\n" << std::flush;
    }
    const auto watch = watcher->add_write_watch_for(file_name.c_str(), file.fd());
    ++file_id;
    inserter->add_file(file_id, file_name);
    hash_file_loop(file_name, file, watch);
}

void hash_engine::hash_file_loop(std::string_view file_name, file_descriptor& file,
    const file_watcher::watch& watch)
{
    for(;;) {
        try {
            const auto modification_time = file.stat().st_mtim;
            try_hash_file(file, watch);
            inserter->finalize_file(file_id, modification_time, file_hash.finalize());
            break;
        } catch(const concurrent_modification_error&) {
            const std::lock_guard guard(*output_mutex);
            *error_output << "File \"" << file_name
                << "\" was modified while hashing, restarting\n" << std::flush;
        }
    }
}

void hash_engine::try_hash_file(file_descriptor& file, const file_watcher::watch& watch)
{
    reset(file);
    for(;;) {
        try_detect_modifications(watch);
        const auto read_data = file.read({buffer.get(), buffer_size});
        if(read_data.empty()) {
            break;
        }
        hash_contents(read_data);
    }
    if(space_left_in_chunk < chunk_size) {
        save_current_chunk();
    }
}

void hash_engine::hash_contents(span<const std::byte> data)
{
    const auto bytes_in_current_chunk = std::min(data.size(), space_left_in_chunk);
    chunk_hash.update(data.first(bytes_in_current_chunk));
    data = data.drop_first(bytes_in_current_chunk);
    space_left_in_chunk -= bytes_in_current_chunk;

    if(!data.empty()) {
        save_current_chunk();
        next_chunk();
        chunk_hash.update(data);
        space_left_in_chunk -= data.size();
    }
}

void hash_engine::save_current_chunk()
{
    const auto chunk_digest = chunk_hash.finalize();
    file_hash.update(chunk_digest);
    inserter->add_chunk(file_id, chunk_id, chunk_digest);
}

void hash_engine::next_chunk() noexcept
{
    ++chunk_id;
    chunk_hash.reset();
    space_left_in_chunk = chunk_size;
}

void hash_engine::reset(file_descriptor& file)
{
    file.rewind();
    space_left_in_chunk = chunk_size;
    chunk_id = 0;
    chunk_hash.reset();
    file_hash.reset();
    inserter->reset_file(file_id);
}

void hash_engine::try_detect_modifications(const file_watcher::watch& watch)
{
    bool detected = false;
    // Process all events, in case there are some belated events for files
    // we processed in the past.
    while(const auto event = watcher->next_event()) {
        if(event->descriptor() == watch.descriptor() && event->is_write_event()) {
            detected = true;
        }
    }
    if(detected) {
        throw concurrent_modification_error();
    }
}

} // namespace filehash
