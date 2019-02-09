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
#ifndef INCLUDED_2F1851206AA24389B884DAF6604E3E8C
#define INCLUDED_2F1851206AA24389B884DAF6604E3E8C
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <string>
#include "blake2sp4.hh"
#include "span.hh"
#include "sqlite.hh"

struct timespec;

namespace filehash::db {

class error final : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class diff;
class hash_inserter;
class mismatched_chunks_cursor;
class mismatched_files_cursor;
class snapshot_cursor;
class snapshot;

class database {
public:
    static void initialize(std::string_view path);

    explicit database(std::string_view path);
    // Disable moves because this class loves keeping parent pointers in all
    // the child object it creates.
    database(database&&) = delete;
    database& operator=(database&&) = delete;

    void save_changes();
    void vacuum();
    std::uint_least64_t integrity_check(std::ostream& error_stream);
    snapshot create_empty_snapshot(std::string_view name);
    snapshot open_snapshot(std::string_view name);
    bool remove_snapshot(std::string_view name);
    diff open_diff(std::string_view old_snapshot_name, std::string_view new_snapshot_name);
private:
    friend class diff;
    friend class hash_inserter;
    friend class snapshot_cursor;
    friend class snapshot;
    friend class mismatched_files_cursor;
    friend class mismatched_chunks_cursor;

    void start_transaction_if_needed();

    sqlite::connection connection;
    sqlite::transaction current_transaction;
};

class snapshot {
public:
    struct metadata {
        std::string_view name;
        timespec start_time;
        timespec end_time;
    };

    hash_inserter start_update(std::size_t worker_id);
    void update_end_time();
private:
    friend class database;

    explicit snapshot(std::int64_t id, database& db) noexcept;

    std::int64_t id;
    database* parent;
};

class hash_inserter {
public:
    void add_file(std::int64_t file_id, std::string_view path);
    void add_chunk(std::int64_t file_id, std::int64_t chunk_id,
        const blake2sp4::result_type& chunk_hash);
    void finalize_file(std::int64_t file_id, const timespec& file_modification_time,
        const blake2sp4::result_type& file_hash);
    void merge_changes();
private:
    friend class snapshot;

    explicit hash_inserter(std::string file_name_table_name, std::string file_data_table_name,
        std::string chunk_table_name, std::int64_t snapshot_id, database& db);

    database* parent;
    sqlite::statement add_chunk_statement;
    sqlite::statement add_file_name_statement;
    sqlite::statement add_file_data_statement;
    std::string file_name_table_name;
    std::string file_data_table_name;
    std::string chunk_table_name;
    std::int64_t snapshot_id;
};

class snapshot_cursor {
public:
    explicit snapshot_cursor(database& db);

    std::optional<snapshot::metadata> next();
private:
    sqlite::owning_cursor<sqlite::string_type_tag, sqlite::blob_type_tag,
        sqlite::blob_type_tag> cursor;
};

class diff {
public:
    struct file_counts {
        std::int64_t equal_files;
        std::int64_t modified_files;
        std::int64_t deleted_files;
        std::int64_t new_files;
    };

    file_counts get_file_counts();
private:
    friend class database;
    friend class mismatched_files_cursor;
    friend class mismatched_chunks_cursor;

    explicit diff(std::int64_t old_snapshot_id, std::int64_t new_snapshot_id, database& db);

    std::int64_t old_snapshot_id;
    std::int64_t new_snapshot_id;
    database* parent;
};

class mismatched_files_cursor {
public:
    struct row_type {
        std::int64_t file_id;
        std::string_view file_path;
        timespec modification_time;
        span<const std::byte> old_hash;
        span<const std::byte> new_hash;
    };

    explicit mismatched_files_cursor(diff& d);

    std::optional<row_type> next();
private:
    sqlite::owning_cursor<sqlite::int_type_tag, sqlite::string_type_tag, sqlite::blob_type_tag,
        sqlite::blob_type_tag, sqlite::blob_type_tag> cursor;
};

class mismatched_chunks_cursor {
public:
    struct row_type {
        std::int64_t chunk_id;
        span<const std::byte> old_hash;
        span<const std::byte> new_hash;
    };

    explicit mismatched_chunks_cursor(diff& d);

    void rewind_to_file(std::int64_t file_id);
    std::optional<row_type> next();
private:
    sqlite::owning_cursor<sqlite::int_type_tag, sqlite::blob_type_tag,
        sqlite::blob_type_tag> cursor;
};

} // namespace filehash::db
#endif
