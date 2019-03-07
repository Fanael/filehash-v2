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
class snapshot;
struct timestamp_column_tag;
struct hash_column_tag;

struct snapshot_metadata {
    std::string_view name;
    timespec start_time;
    timespec end_time;

    FILEHASH_SQLITE_REGISTER_ROW_TYPE(sqlite::string_column_tag,
        timestamp_column_tag,
        timestamp_column_tag);
};

struct mismatched_file {
    std::int64_t file_id;
    std::string_view file_path;
    timespec modification_time;
    span<const std::byte> old_hash;
    span<const std::byte> new_hash;

    FILEHASH_SQLITE_REGISTER_ROW_TYPE(sqlite::int_column_tag,
        sqlite::string_column_tag,
        timestamp_column_tag,
        hash_column_tag,
        hash_column_tag);
};

struct full_diff_mismatched_file {
    std::int64_t old_snapshot_id;
    std::int64_t new_snapshot_id;
    std::string_view old_snapshot_name;
    std::string_view new_snapshot_name;
    std::int64_t file_id;
    std::string_view file_path;
    timespec modification_time;
    span<const std::byte> old_hash;
    span<const std::byte> new_hash;

    FILEHASH_SQLITE_REGISTER_ROW_TYPE(sqlite::int_column_tag,
        sqlite::int_column_tag,
        sqlite::string_column_tag,
        sqlite::string_column_tag,
        sqlite::int_column_tag,
        sqlite::string_column_tag,
        timestamp_column_tag,
        hash_column_tag,
        hash_column_tag);
};

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
    sqlite::owning_cursor<snapshot_metadata> open_snapshot_cursor();
    diff open_diff(std::string_view old_snapshot_name, std::string_view new_snapshot_name);
    sqlite::owning_cursor<full_diff_mismatched_file> open_full_diff();
    mismatched_chunks_cursor open_chunk_mismatch_cursor();
private:
    friend class diff;
    friend class hash_inserter;
    friend class mismatched_chunks_cursor;
    friend class snapshot;

    void start_transaction_if_needed();

    sqlite::connection connection;
    sqlite::transaction current_transaction;
};

class snapshot {
public:
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

class diff {
public:
    struct file_counts {
        std::int64_t equal_files;
        std::int64_t modified_files;
        std::int64_t deleted_files;
        std::int64_t new_files;

        FILEHASH_SQLITE_REGISTER_ROW_TYPE(sqlite::int_column_tag,
            sqlite::int_column_tag,
            sqlite::int_column_tag,
            sqlite::int_column_tag);
    };

    file_counts get_file_counts();
    sqlite::owning_cursor<mismatched_file> open_file_mismatch_cursor();
    mismatched_chunks_cursor open_chunk_mismatch_cursor();
private:
    friend class database;

    explicit diff(std::int64_t old_snapshot_id, std::int64_t new_snapshot_id, database& db);

    std::int64_t old_snapshot_id;
    std::int64_t new_snapshot_id;
    database* parent;
};

class mismatched_chunks_cursor {
public:
    struct row_type {
        std::int64_t chunk_id;
        span<const std::byte> old_hash;
        span<const std::byte> new_hash;

        FILEHASH_SQLITE_REGISTER_ROW_TYPE(sqlite::int_column_tag,
            hash_column_tag,
            hash_column_tag);
    };

    void rewind_to_file(std::int64_t file_id);
    void rewind_to_file_in(std::int64_t file_id, std::int64_t old_snapshot_id,
        std::int64_t new_snapshot_id);
    std::optional<row_type> next();
private:
    friend class database;
    friend class diff;

    explicit mismatched_chunks_cursor(database& db);

    sqlite::owning_cursor<row_type> cursor;
};

struct timestamp_column_tag {
    using raw_tag = sqlite::blob_column_tag;
    using column_type = timespec;

    static column_type transform(span<const std::byte> blob);
};

struct hash_column_tag {
    using raw_tag = sqlite::blob_column_tag;
    using column_type = span<const std::byte>;

    static column_type transform(span<const std::byte> blob);
};

} // namespace filehash::db
#endif
