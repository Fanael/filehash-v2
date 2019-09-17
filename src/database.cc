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
#include <memory>
#include <ostream>
#include <string_view>
#include <string>
#include <type_traits>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <time.h>
#include "database.hh"
#include "span.hh"
#include "sqlite.hh"
#include "temporary-table.hh"

namespace filehash::db {
namespace {

// We need this as a macro to stringify it.
// For those curious, the value was randomly generated and means nothing
// at all.
#define FILEHASH_APPLICATION_ID -560804911

constexpr std::int32_t our_application_id = FILEHASH_APPLICATION_ID;

sqlite::connection open_database(std::string_view path, sqlite::open_mode mode)
{
    // Grow the database in 1 MB chunks to reduce fragmentation.
    constexpr int default_chunk_size = 1048576;
    // Wait 5 seconds for the database to be unlocked.
    constexpr int default_busy_timeout = 5000;

    // Ensure the user cannot pass magic SQLite names like ":memory:".
    const auto safe_path = (boost::starts_with(path, ":") || boost::starts_with(path, "file:"))
        ? std::string("./").append(path)
        : std::string(path);

    sqlite::connection connection(safe_path.c_str(), mode);
    connection.set_chunk_size(default_chunk_size);
    connection.set_busy_timeout(default_busy_timeout);
    return connection;
}

void apply_common_pragmas(sqlite::connection& connection)
{
    connection.execute("PRAGMA journal_mode = WAL;");
    connection.execute("PRAGMA automatic_index = OFF;");
    connection.execute("PRAGMA cache_size = -16384;");
    connection.execute("PRAGMA foreign_keys = ON;");
    connection.execute("PRAGMA secure_delete = OFF;");
    connection.execute("PRAGMA synchronous = FULL;");
}

void check_application_id(sqlite::connection& connection)
{
    auto stmt = connection.prepare("PRAGMA application_id;");
    const auto id = stmt.get_single_row_always<std::int64_t>();
    if(id != our_application_id) {
        throw error("Not a valid database file, wrong application_id: " + std::to_string(id));
    }
}


// 12-byte, epoch-relative UTC timestamp using offset binary for the seconds
// field so that byte-for-byte ordering using memcmp results in correct
// ordering.
struct serialized_timestamp {
    std::array<std::byte, sizeof(std::uint64_t)> seconds_bytes;
    std::array<std::byte, sizeof(std::uint32_t)> nanoseconds_bytes;
};

static_assert(std::is_standard_layout_v<serialized_timestamp>);
static_assert(std::is_trivial_v<serialized_timestamp>);
static_assert(sizeof(serialized_timestamp) == 12);

constexpr std::uint64_t convert_2s_complement_and_offset_binary(std::uint64_t value) noexcept
{
    return value ^ (std::uint64_t{1} << 63);
}

template <typename To, typename From>
To bit_cast(const From& source) noexcept
{
    static_assert(std::is_trivially_copyable_v<From>);
    static_assert(std::is_trivial_v<To>);
    static_assert(sizeof(To) == sizeof(From));

    To result;
    std::memcpy(std::addressof(result), std::addressof(source), sizeof(To));
    return result;
}

template <typename To, typename From>
void bit_cast_assign(To& destination, const From& source) noexcept
{
    destination = bit_cast<To>(source);
}

serialized_timestamp serialize_timestamp(const timespec& ts) noexcept
{
    serialized_timestamp result;
    bit_cast_assign(result.seconds_bytes, boost::endian::native_to_big(
        convert_2s_complement_and_offset_binary(static_cast<std::uint64_t>(
            static_cast<std::int64_t>(ts.tv_sec)))));
    bit_cast_assign(result.nanoseconds_bytes, boost::endian::native_to_big(
        static_cast<std::uint32_t>(ts.tv_nsec)));
    return result;
}

timespec deserialize_timestamp(span<const std::byte> bytes)
{
    if(bytes.size_bytes() != sizeof(serialized_timestamp)) {
        throw error("Invalid timestamp size found in database: "
            + std::to_string(bytes.size_bytes()) + " bytes");
    }
    serialized_timestamp serialized;
    std::memcpy(&serialized, bytes.data(), sizeof(serialized));
    timespec result;
    result.tv_sec = static_cast<time_t>(convert_2s_complement_and_offset_binary(
        boost::endian::big_to_native(bit_cast<std::uint64_t>(serialized.seconds_bytes))));
    result.tv_nsec = static_cast<long>(boost::endian::big_to_native(bit_cast<std::uint32_t>(
        serialized.nanoseconds_bytes)));
    return result;
}


timespec current_time() noexcept
{
    timespec result;
    clock_gettime(CLOCK_REALTIME, &result);
    return result;
}


sqlite::statement make_statement_lookup_statement(sqlite::connection& connection)
{
    return connection.prepare("SELECT snapshot_id FROM snapshots WHERE name = ?;");
}

std::optional<std::int64_t> try_get_snapshot_id(sqlite::statement& lookup_stmt,
    std::string_view name)
{
    lookup_stmt.reset();
    lookup_stmt.bind(name);
    return lookup_stmt.get_single_row<std::int64_t>();
}

std::int64_t get_snapshot_id(sqlite::statement& lookup_stmt, std::string_view name)
{
    const auto snapshot_id = try_get_snapshot_id(lookup_stmt, name);
    if(!snapshot_id) {
        throw error(std::string("no snapshot named \"").append(name).append("\" found"));
    }
    return *snapshot_id;
}


std::uint_least64_t check_sqlite_integrity(sqlite::connection& connection,
    std::ostream& error_stream)
{
    error_stream << "Running PRAGMA integrity_check... " << std::flush;
    // SQLite always limits the number of messages returned from
    // integrity_check, there's no way to make it return *all* messages.
    // So limit the number of error messages to a thousand, because if
    // a database has more errors than that, it's likely unsalvageable.
    sqlite::owning_cursor<std::string_view> cursor(
        connection.prepare("PRAGMA integrity_check(1000);"));
    std::uint_least64_t total_errors = 0;
    while(const auto string = cursor.next()) {
        if(total_errors == 0) {
            if(*string == std::string_view("ok")) {
                continue;
            }
            error_stream << "ERROR!\n";
        }
        ++total_errors;
        error_stream << *string << '\n' << std::flush;
    }
    if(total_errors == 0) {
        error_stream << "ok\n";
    }
    return total_errors;
}

std::uint_least64_t check_sqlite_foreign_keys(sqlite::connection& connection,
    std::ostream& error_stream)
{
    struct foreign_key_violation {
        FILEHASH_SQLITE_DEFINE_ROW_TYPE(
            ((sqlite::string_column_tag)(child_table_name))
            ((sqlite::nullable_int_column_tag)(child_rowid))
            ((sqlite::string_column_tag)(parent_table_name))
            ((sqlite::int_column_tag)(constraint_id)));
    };

    error_stream << "Running PRAGMA foreign_key_check... " << std::flush;
    sqlite::owning_cursor<foreign_key_violation> cursor(connection.prepare(
        "PRAGMA foreign_key_check;"));
    std::uint_least64_t total_errors = 0;
    while(const auto row = cursor.next()) {
        if(total_errors == 0) {
            error_stream << "ERROR!\n";
        }
        ++total_errors;
        error_stream << "Foreign key constraint failed:\n  Child table: " << row->child_table_name
            << "\n  Parent table: " << row->parent_table_name << "\n  Foreign key ID: "
            << row->constraint_id << "\n  Child table rowid: ";
        if(row->child_rowid) {
            error_stream << *row->child_rowid;
        } else {
            error_stream << "(NULL)";
        }
        error_stream << '\n' << std::flush;
    }
    if(total_errors == 0) {
        error_stream << "ok\n";
    }
    return total_errors;
}

std::uint_least64_t check_file_hashes(sqlite::connection& connection, std::ostream& error_stream)
{
    struct file_row {
        FILEHASH_SQLITE_DEFINE_ROW_TYPE(
            ((sqlite::int_column_tag)(snapshot_id))
            ((sqlite::int_column_tag)(path_id))
            ((hash_column_tag)(hash)));
    };

    error_stream << "Looking for file hash mismatches... " << std::flush;
    sqlite::owning_cursor<file_row> file_cursor(connection.prepare(
        "SELECT snapshot_id, path_id, hash "
        "FROM snapshot_files "
        "JOIN hashes USING (hash_id);"));
    sqlite::owning_cursor<span<const std::byte>> file_chunk_cursor(connection.prepare(
        "SELECT hash "
        "FROM file_chunks "
        "JOIN hashes USING (hash_id) "
        "WHERE snapshot_id = ? AND path_id = ? "
        "ORDER BY chunk_id ASC;"));
    std::uint_least64_t total_errors = 0;
    while(const auto file = file_cursor.next()) {
        file_chunk_cursor.rewind();
        file_chunk_cursor.bind(file->snapshot_id, file->path_id);

        blake2sp4 hash_engine;
        while(const auto chunk_hash = file_chunk_cursor.next()) {
            hash_engine.update(*chunk_hash);
        }
        const auto db_hash = file->hash;
        const auto actual_hash = hash_engine.finalize();
        if(std::equal(db_hash.begin(), db_hash.end(), actual_hash.begin(), actual_hash.end())) {
            continue;
        }
        // Hashes don't match, it's an error.
        if(total_errors == 0) {
            error_stream << "ERROR!\n";
        }
        ++total_errors;
        error_stream << "The hash of file ID " << file->path_id << " in snapshot ID "
            << file->snapshot_id << " doesn't match the hash of its chunks' hashes.\n"
            << std::flush;
    }
    if(total_errors == 0) {
        error_stream << "ok\n";
    }
    return total_errors;
}

} // unnamed namespace

void database::initialize(std::string_view path)
{
    auto connection = open_database(path, sqlite::open_mode::create_new);
    connection.execute("PRAGMA page_size = 8192;");
    connection.execute("PRAGMA encoding = \"UTF-8\"");
    connection.execute("PRAGMA application_id = " BOOST_PP_STRINGIZE(FILEHASH_APPLICATION_ID));
    apply_common_pragmas(connection);
    auto transaction = connection.begin_transaction();
    connection.execute(R"eof(
CREATE TABLE snapshots (
    snapshot_id INTEGER NOT NULL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    start_time BLOB NOT NULL,
    end_time BLOB NOT NULL,
    CONSTRAINT start_time_type CHECK(typeof(start_time) = 'blob' AND length(start_time) = 12),
    CONSTRAINT end_time_type CHECK(typeof(end_time) = 'blob' AND length(end_time) = 12)
);)eof");
    connection.execute(R"eof(
CREATE TABLE paths (
    path_id INTEGER NOT NULL PRIMARY KEY,
    path TEXT NOT NULL UNIQUE
);)eof");
    connection.execute(R"eof(
CREATE TABLE hashes (
    hash_id INTEGER NOT NULL PRIMARY KEY,
    hash BLOB NOT NULL UNIQUE,
    CONSTRAINT hash_type CHECK(typeof(hash) = 'blob' AND length(hash) = 32)
);)eof");
    connection.execute(R"eof(
CREATE TABLE snapshot_files (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    path_id INTEGER NOT NULL REFERENCES paths(path_id),
    mod_time BLOB NOT NULL,
    hash_id INTEGER NOT NULL REFERENCES hashes(hash_id),
    PRIMARY KEY(snapshot_id, path_id),
    CONSTRAINT mod_time_type CHECK(typeof(mod_time) = 'blob' AND length(mod_time) = 12)
) WITHOUT ROWID;)eof");
    connection.execute(R"eof(
CREATE TABLE file_chunks (
    snapshot_id INTEGER NOT NULL,
    path_id INTEGER NOT NULL,
    chunk_id INTEGER NOT NULL,
    hash_id INTEGER NOT NULL REFERENCES hashes(hash_id),
    PRIMARY KEY(snapshot_id, path_id, chunk_id),
    FOREIGN KEY(snapshot_id, path_id) REFERENCES snapshot_files(snapshot_id, path_id)
        ON DELETE CASCADE
) WITHOUT ROWID;)eof");
    transaction.commit();
}

database::database(std::string_view path)
    : connection(open_database(path, sqlite::open_mode::open_existing)),
      current_transaction(sqlite::invalid_transaction_tag)
{
    // Some of the pragmas need to be applied outside of an transaction,
    // which we start only when first needed anyway.
    apply_common_pragmas(connection);
    check_application_id(connection);
}

void database::save_changes()
{
    if(current_transaction.valid()) {
        current_transaction.commit();
    }
}

void database::vacuum()
{
    start_transaction_if_needed();
    // Get rid of unreferenced paths and hashes, but create temporary
    // indices first so that foreign key enforcement doesn't require full
    // table scans.
    connection.execute("CREATE INDEX snapshot_file_paths ON snapshot_files(path_id);");
    connection.execute("CREATE INDEX snapshot_file_hashes ON snapshot_files(hash_id);");
    connection.execute("CREATE INDEX file_chunk_hashes ON file_chunks(hash_id);");
    connection.execute("DELETE FROM hashes "
        "WHERE hash_id NOT IN (SELECT hash_id FROM snapshot_files) "
        "  AND hash_id NOT IN (SELECT hash_id FROM file_chunks);");
    // NB: not needed to read file_chunks.path_id because it's a part
    // of a foreign key against snapshot_files anyway.
    connection.execute(
        "DELETE FROM paths WHERE path_id NOT IN (SELECT path_id FROM snapshot_files);");
    connection.execute("DROP INDEX snapshot_file_paths;");
    connection.execute("DROP INDEX snapshot_file_hashes;");
    connection.execute("DROP INDEX file_chunk_hashes;");
    // We need to commit the transaction because VACUUM cannot be run in one.
    save_changes();
    connection.execute("VACUUM;");
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE);");
}

std::uint_least64_t database::integrity_check(std::ostream& error_stream)
{
    start_transaction_if_needed();
    // Run this first because if it fails, the database file is unreliable
    // and we don't want to do anything else.
    const auto integrity_errors = check_sqlite_integrity(connection, error_stream);
    if(integrity_errors > 0) {
        return integrity_errors;
    }
    const auto foreign_key_errors = check_sqlite_foreign_keys(connection, error_stream);
    const auto file_hash_mismatch_error = check_file_hashes(connection, error_stream);
    return foreign_key_errors + file_hash_mismatch_error;
}

snapshot database::create_empty_snapshot(std::string_view name)
{
    start_transaction_if_needed();
    const auto snapshot_start_time = serialize_timestamp(current_time());
    const auto timestamp_bytes = as_bytes(span(&snapshot_start_time, 1));
    auto stmt = connection.prepare(
        "INSERT INTO snapshots (name, start_time, end_time) VALUES (?, ?, ?)");
    stmt.bind(name, timestamp_bytes, timestamp_bytes);
    stmt.step();
    return snapshot(connection.last_insert_rowid(), *this);
}

std::optional<snapshot> database::try_open_snapshot(std::string_view name)
{
    start_transaction_if_needed();
    auto stmt = make_statement_lookup_statement(connection);
    const auto snapshot_id = try_get_snapshot_id(stmt, name);
    return snapshot_id ? std::optional(snapshot(*snapshot_id, *this)) : std::nullopt;
}

snapshot database::open_snapshot(std::string_view name)
{
    start_transaction_if_needed();
    auto stmt = make_statement_lookup_statement(connection);
    return snapshot(get_snapshot_id(stmt, name), *this);
}

sqlite::restricted_owning_cursor<snapshot_metadata> database::open_snapshot_cursor()
{
    start_transaction_if_needed();
    return sqlite::restricted_owning_cursor<snapshot_metadata>(connection.prepare(
        "SELECT name, start_time, end_time FROM snapshots ORDER BY start_time DESC;"));
}

diff database::open_diff(std::string_view old_snapshot_name, std::string_view new_snapshot_name)
{
    start_transaction_if_needed();
    auto stmt = make_statement_lookup_statement(connection);
    const auto old_snapshot_id = get_snapshot_id(stmt, old_snapshot_name);
    const auto new_snapshot_id = get_snapshot_id(stmt, new_snapshot_name);
    return diff(old_snapshot_id, new_snapshot_id, *this);
}

sqlite::restricted_owning_cursor<full_diff_mismatched_file> database::open_full_diff()
{
    start_transaction_if_needed();
    return sqlite::restricted_owning_cursor<full_diff_mismatched_file>(connection.prepare(R"eof(
SELECT
  sids.snapshot_id AS old_snapshot_id,
  sids.successor_id AS new_snapshot_id,
  sids.name AS old_snapshot_name,
  sids.successor_name AS new_snapshot_name,
  old_s.path_id AS path_id,
  p.path AS path,
  old_s.mod_time AS modification_time,
  old_h.hash AS old_hash,
  new_h.hash AS new_hash
FROM (
  SELECT *
  FROM (
    SELECT
      snapshot_id,
      LEAD(snapshot_id) OVER w AS successor_id,
      name,
      LEAD(name) OVER w AS successor_name
    FROM snapshots
    WINDOW w AS (ORDER BY start_time ASC))
  WHERE successor_id IS NOT NULL) AS sids
JOIN snapshot_files AS old_s ON old_s.snapshot_id = sids.snapshot_id
JOIN snapshot_files AS new_s
  ON new_s.snapshot_id = sids.successor_id
 AND old_s.path_id = new_s.path_id
 AND old_s.mod_time = new_s.mod_time
 AND old_s.hash_id <> new_s.hash_id
JOIN paths AS p ON old_s.path_id = p.path_id
JOIN hashes AS old_h ON old_s.hash_id = old_h.hash_id
JOIN hashes AS new_h ON new_s.hash_id = new_h.hash_id;)eof"));
}

mismatched_chunks_cursor database::open_chunk_mismatch_cursor()
{
    start_transaction_if_needed();
    return mismatched_chunks_cursor(*this);
}

collection_set database::open_collection_set()
{
    start_transaction_if_needed();
    auto table_guard = sqlite::make_temporary_table(connection,
        "CREATE TABLE temp.snapshot_collection_set (snapshot_id INTEGER NOT NULL PRIMARY KEY);",
        "DROP TABLE temp.snapshot_collection_set");
    auto add_snapshot = connection.prepare("INSERT INTO temp.snapshot_collection_set VALUES (?);");
    auto remove = connection.prepare("DELETE FROM snapshots WHERE snapshot_id IN ("
        "SELECT snapshot_id FROM temp.snapshot_collection_set);");
    return collection_set(std::move(table_guard), std::move(add_snapshot), std::move(remove));
}

void database::start_transaction_if_needed()
{
    if(!current_transaction.valid()) {
        current_transaction = connection.begin_transaction();
    }
}


snapshot::snapshot(std::int64_t id, database& db) noexcept
    : id(id), parent(&db)
{
}

hash_inserter snapshot::start_update(std::size_t worker_id)
{
    const auto worker_id_str = std::to_string(worker_id);
    auto file_name_table_name = "temp.file_names_" + worker_id_str;
    auto file_data_table_name = "temp.file_data_" + worker_id_str;
    auto chunk_table_name = "temp.file_chunks_" + worker_id_str;

    parent->connection.execute("CREATE TABLE " + file_name_table_name + " ("
        "file_id INTEGER NOT NULL PRIMARY KEY, "
        "path TEXT NOT NULL);");
    parent->connection.execute("CREATE TABLE " + file_data_table_name + " ("
        "file_id INTEGER NOT NULL PRIMARY KEY, "
        "mod_time BLOB NOT NULL, "
        "hash BLOB NOT NULL);");
    parent->connection.execute("CREATE TABLE " + chunk_table_name + " ("
        "file_id INTEGER NOT NULL, "
        "chunk_id INTEGER NOT NULL, "
        "hash BLOB NOT NULL, "
        "PRIMARY KEY(file_id, chunk_id)) WITHOUT ROWID;");

    return hash_inserter(std::move(file_name_table_name), std::move(file_data_table_name),
        std::move(chunk_table_name), id, *parent);
}

void snapshot::update_end_time()
{
    const auto snapshot_start_time = serialize_timestamp(current_time());
    const auto timestamp_bytes = as_bytes(span(&snapshot_start_time, 1));
    auto stmt = parent->connection.prepare(
        "UPDATE snapshots SET end_time = ? WHERE snapshot_id = ?;");
    stmt.bind(timestamp_bytes, id);
    stmt.step();
}


void hash_inserter::merge_changes()
{
    // Add paths and hashes to the deduplication tables first, so that
    // everything can be done in bulk.
    parent->connection.execute(
        "INSERT INTO paths(path) SELECT path FROM " + file_name_table_name
        + " WHERE TRUE ON CONFLICT(path) DO NOTHING;");
    parent->connection.execute(
        "INSERT INTO hashes(hash) SELECT hash FROM " + file_data_table_name
        + " WHERE TRUE ON CONFLICT(hash) DO NOTHING;");
    parent->connection.execute(
        "INSERT INTO hashes(hash) SELECT hash FROM " + chunk_table_name
        + " WHERE TRUE ON CONFLICT(hash) DO NOTHING;");

    auto add_files_statement = parent->connection.prepare(
        "INSERT OR REPLACE INTO snapshot_files(snapshot_id, path_id, mod_time, hash_id) SELECT "
        "?, "
        "(SELECT path_id FROM paths WHERE path = fn.path), "
        "fd.mod_time, "
        "(SELECT hash_id FROM hashes WHERE hash = fd.hash) "
        "FROM " + file_data_table_name + " AS fd "
        "JOIN " + file_name_table_name + " AS fn USING (file_id);");
    add_files_statement.bind(snapshot_id);
    add_files_statement.step();

    auto add_chunks_statement = parent->connection.prepare(
        "INSERT OR REPLACE INTO file_chunks(snapshot_id, path_id, chunk_id, hash_id) SELECT "
        "?, "
        "(SELECT path_id FROM paths WHERE path = fn.path), "
        "c.chunk_id, "
        "(SELECT hash_id FROM hashes WHERE hash = c.hash) "
        "FROM " + chunk_table_name + " AS c "
        "JOIN " + file_name_table_name + " AS fn USING (file_id);");
    add_chunks_statement.bind(snapshot_id);
    add_chunks_statement.step();
}

hash_inserter::hash_inserter(std::string file_name_table_name, std::string file_data_table_name,
    std::string chunk_table_name, std::int64_t snapshot_id, database& db)
    : parent(&db),
      add_chunk_statement(db.connection.prepare(
          "INSERT INTO " + chunk_table_name + " VALUES (?, ?, ?)")),
      add_file_name_statement(db.connection.prepare(
          "INSERT INTO " + file_name_table_name + " VALUES (?, ?)")),
      add_file_data_statement(db.connection.prepare(
          "INSERT INTO " + file_data_table_name + " VALUES (?, ?, ?)")),
      file_name_table_name(std::move(file_name_table_name)),
      file_data_table_name(std::move(file_data_table_name)),
      chunk_table_name(std::move(chunk_table_name)),
      snapshot_id(snapshot_id)
{
}

void hash_inserter::add_file(std::int64_t file_id, std::string_view path)
{
    add_file_name_statement.reset();
    add_file_name_statement.bind(file_id, path);
    add_file_name_statement.step();
}

void hash_inserter::reset_file(std::int64_t file_id)
{
    auto remove_chunks_statement = parent->connection.prepare(
        "DELETE FROM " + chunk_table_name + " WHERE file_id = ?;");
    remove_chunks_statement.bind(file_id);
    remove_chunks_statement.step();
}

void hash_inserter::add_chunk(std::int64_t file_id, std::int64_t chunk_id,
    const blake2sp4::result_type& chunk_hash)
{
    add_chunk_statement.reset();
    add_chunk_statement.bind(file_id, chunk_id, chunk_hash);
    add_chunk_statement.step();
}

void hash_inserter::finalize_file(std::int64_t file_id, const timespec& file_modification_time,
    const blake2sp4::result_type& file_hash)
{
    const auto serialized_modification_time = serialize_timestamp(file_modification_time);
    const auto modification_time_bytes = as_bytes(span(&serialized_modification_time, 1));
    add_file_data_statement.reset();
    add_file_data_statement.bind(file_id, modification_time_bytes, file_hash);
    add_file_data_statement.step();
}


auto diff::get_file_counts() -> file_counts
{
    auto stmt = parent->connection.prepare(R"eof(
SELECT
  same_files,
  modified_files,
  deleted_files,
  new_snapshot_files - old_snapshot_files + deleted_files
FROM (
  SELECT
    COALESCE(SUM(old_s.mod_time = new_s.mod_time), 0) AS same_files,
    COALESCE(SUM(old_s.mod_time <> new_s.mod_time), 0) AS modified_files,
    COALESCE(SUM(new_s.mod_time IS NULL), 0) AS deleted_files,
    (SELECT COUNT(*) FROM snapshot_files WHERE snapshot_id = ?) AS old_snapshot_files,
    (SELECT COUNT(*) FROM snapshot_files WHERE snapshot_id = ?) AS new_snapshot_files
  FROM snapshot_files AS old_s
  LEFT JOIN snapshot_files AS new_s ON new_s.snapshot_id = ?2 AND old_s.path_id = new_s.path_id
  WHERE old_s.snapshot_id = ?1);)eof");
    stmt.bind(old_snapshot_id, new_snapshot_id);
    return stmt.get_single_row_always<file_counts>();
}

sqlite::restricted_owning_cursor<mismatched_file> diff::open_file_mismatch_cursor()
{
    auto stmt = parent->connection.prepare(R"eof(
SELECT
  old_s.path_id AS path_id,
  p.path AS path,
  old_s.mod_time AS modification_time,
  old_h.hash AS old_hash,
  new_h.hash AS new_hash
FROM snapshot_files AS old_s
JOIN snapshot_files AS new_s
  ON old_s.path_id = new_s.path_id
 AND old_s.mod_time = new_s.mod_time
 AND old_s.hash_id <> new_s.hash_id
JOIN paths AS p ON old_s.path_id = p.path_id
JOIN hashes AS old_h ON old_s.hash_id = old_h.hash_id
JOIN hashes AS new_h ON new_s.hash_id = new_h.hash_id
WHERE old_s.snapshot_id = ?
  AND new_s.snapshot_id = ?;)eof");
    stmt.bind(old_snapshot_id, new_snapshot_id);
    return sqlite::restricted_owning_cursor<mismatched_file>(std::move(stmt));
}

mismatched_chunks_cursor diff::open_chunk_mismatch_cursor()
{
    mismatched_chunks_cursor result(*parent);
    result.cursor.bind(old_snapshot_id, new_snapshot_id);
    return result;
}

diff::diff(std::int64_t old_snapshot_id, std::int64_t new_snapshot_id, database& db)
    : old_snapshot_id(old_snapshot_id),
      new_snapshot_id(new_snapshot_id),
      parent(&db)
{
}


void mismatched_chunks_cursor::rewind_to_file(std::int64_t file_id)
{
    cursor.rewind();
    cursor.bind_one(3, file_id);
}

void mismatched_chunks_cursor::rewind_to_file_in(std::int64_t file_id, std::int64_t old_snapshot_id,
    std::int64_t new_snapshot_id)
{
    cursor.rewind();
    cursor.bind(old_snapshot_id, new_snapshot_id, file_id);
}

auto mismatched_chunks_cursor::next() -> std::optional<row_type>
{
    return cursor.next();
}

mismatched_chunks_cursor::mismatched_chunks_cursor(database& db)
    : cursor(db.connection.prepare(R"eof(
SELECT
  old_s.chunk_id AS chunk_id,
  old_h.hash AS old_hash,
  new_h.hash AS new_hash
FROM file_chunks AS old_s
JOIN file_chunks AS new_s
  ON old_s.path_id = new_s.path_id
 AND old_s.chunk_id = new_s.chunk_id
 AND old_s.hash_id <> new_s.hash_id
JOIN hashes AS old_h ON old_s.hash_id = old_h.hash_id
JOIN hashes AS new_h ON new_s.hash_id = new_h.hash_id
WHERE old_s.snapshot_id = ?
  AND new_s.snapshot_id = ?
  AND old_s.path_id = ?;)eof"))
{
}


void collection_set::add_snapshot(snapshot&& snapshot)
{
    add_snapshot_statement.reset();
    add_snapshot_statement.bind(snapshot.id);
    add_snapshot_statement.step();
}

void collection_set::remove_snapshots()
{
    remove_snapshots_statement.reset();
    remove_snapshots_statement.step();
}

collection_set::collection_set(sqlite::temporary_table_guard guard, sqlite::statement add_snapshot,
    sqlite::statement remove_snapshots) noexcept
    : table_guard(std::move(guard)),
      add_snapshot_statement(std::move(add_snapshot)),
      remove_snapshots_statement(std::move(remove_snapshots))
{
}


auto timestamp_column_tag::transform(span<const std::byte> blob) -> column_type
{
    return deserialize_timestamp(blob);
}

auto hash_column_tag::transform(span<const std::byte> blob) -> column_type
{
    const auto blob_size = blob.size_bytes();
    if(blob_size != sizeof(blake2sp4::result_type)) {
        throw error("Invalid hash size found in database: " + std::to_string(blob_size) + " bytes");
    }
    return blob;
}

} // namespace filehash::db
