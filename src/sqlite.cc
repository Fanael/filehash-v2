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
#include <exception>
#include <string>
#include <sqlite3.h>
#include "compiler.hh"
#include "span.hh"
#include "sqlite.hh"

namespace filehash::sqlite {

error::error(const char* message)
    : std::runtime_error(message)
{
}


namespace {

[[noreturn]] void throw_error(const char* message)
{
    throw error(message);
}

[[noreturn]] void throw_error(int error_code)
{
    throw_error(sqlite3_errstr(error_code));
}

[[noreturn]] void throw_error(sqlite3* db)
{
    throw_error(sqlite3_errmsg(db));
}

[[noreturn]] void throw_error(sqlite3_stmt* statement)
{
    throw_error(sqlite3_db_handle(statement));
}

int get_error_code(sqlite3_stmt* statement) noexcept
{
    return sqlite3_errcode(sqlite3_db_handle(statement));
}

void initialize_sqlite()
{
    struct initializer {
        initializer()
        {
            const auto status = sqlite3_initialize();
            if(status != SQLITE_OK) {
                throw_error(status);
            }
        }
        ~initializer()
        {
            sqlite3_shutdown();
        }
    };
    static initializer init;
}

constexpr int mode_to_flags(open_mode mode) noexcept
{
    switch(mode) {
    case open_mode::open_existing: return 0;
    case open_mode::create_new: return SQLITE_OPEN_CREATE;
    }
    FILEHASH_UNREACHABLE();
}

} // unnamed namespace

void statement::reset() noexcept
{
    sqlite3_reset(handle.get());
}

bool statement::step()
{
    const auto status = sqlite3_step(handle.get());
    switch(status) {
    case SQLITE_DONE: return false;
    case SQLITE_ROW: return true;
    default:
        // If sqlite3_step fails, the precise error message may be set
        // only in the statement object, not the database, and reset is what
        // causes it to be copied to the database.
        reset();
        throw_error(handle.get());
    }
}

void statement::bind_one(int parameter_id, std::int64_t value)
{
    const auto status = sqlite3_bind_int64(handle.get(), parameter_id, value);
    if(status != SQLITE_OK) {
        throw_error(handle.get());
    }
}

void statement::bind_one(int parameter_id, span<const std::byte> value)
{
    const auto status = sqlite3_bind_blob64(handle.get(), parameter_id, value.data(),
        value.size_bytes(), SQLITE_STATIC);
    if(status != SQLITE_OK) {
        throw_error(handle.get());
    }
}

void statement::bind_one(int parameter_id, std::string_view value)
{
    const auto status = sqlite3_bind_text64(handle.get(), parameter_id, value.data(), value.size(),
        SQLITE_STATIC, SQLITE_UTF8);
    if(status != SQLITE_OK) {
        throw_error(handle.get());
    }
}

statement::statement(sqlite3_stmt* statement) noexcept
    : handle(statement)
{
}

[[noreturn]] void statement::throw_no_rows_error()
{
    throw_error("no rows returned from a statement that should always return some");
}

void statement::check_column_count(std::size_t column_count) const
{
    const auto actual_column_count = sqlite3_column_count(handle.get());
    if(actual_column_count < 0 || column_count > static_cast<unsigned>(actual_column_count)) {
        throw_error(SQLITE_RANGE);
    }
}

std::int64_t statement::get(int column_id, int_type_tag) noexcept
{
    // NB: column_id not checked because it's checked ahead of time when
    // creating a cursor.
    return sqlite3_column_int64(handle.get(), column_id);
}

span<const std::byte> statement::get(int column_id, blob_type_tag)
{
    // NB: column_id not checked because it's checked ahead of time when
    // creating a cursor.
    const auto data = sqlite3_column_blob(handle.get(), column_id);
    if(data == nullptr && get_error_code(handle.get()) == SQLITE_NOMEM) {
        throw_error(SQLITE_NOMEM);
    }
    const auto size = sqlite3_column_bytes(handle.get(), column_id);
    return {static_cast<const std::byte*>(data), static_cast<unsigned>(size)};
}

std::string_view statement::get(int column_id, string_type_tag)
{
    // NB: column_id not checked because it's checked ahead of time when
    // creating a cursor.
    const auto data = sqlite3_column_text(handle.get(), column_id);
    if(data == nullptr && get_error_code(handle.get()) == SQLITE_NOMEM) {
        throw_error(SQLITE_NOMEM);
    }
    const auto size = sqlite3_column_bytes(handle.get(), column_id);
    return {reinterpret_cast<const char*>(data), static_cast<unsigned>(size)};
}

void statement::deleter::operator()(sqlite3_stmt* stmt) const noexcept
{
    sqlite3_finalize(stmt);
}


connection::connection(const char* file_name, open_mode mode)
    : handle(open(file_name, mode)),
      begin_transaction_statement(prepare("BEGIN;")),
      commit_statement(prepare("COMMIT;")),
      rollback_statement(prepare("ROLLBACK;"))
{
    // Check if it's really a new database that we just opened.
    if(mode == open_mode::create_new) {
        const auto schema_version =
            std::get<0>(prepare("PRAGMA schema_version;").get_single_row_always(int_tag));
        if(schema_version != 0) {
            throw_error("database already exists");
        }
    }
}

void connection::set_busy_timeout(int milliseconds)
{
    const auto status = sqlite3_busy_timeout(handle.get(), milliseconds);
    if(status != SQLITE_OK) {
        throw_error(handle.get());
    }
}

void connection::set_chunk_size(int chunk_size, const char* database)
{
    // The intended use of this function is as a *hint*, so don't check
    // if the call succeeded.
    sqlite3_file_control(handle.get(), database, SQLITE_FCNTL_CHUNK_SIZE, &chunk_size);
}

std::int64_t connection::last_insert_rowid() const noexcept
{
    return sqlite3_last_insert_rowid(handle.get());
}

int connection::change_count() const noexcept
{
    return sqlite3_changes(handle.get());
}

bool connection::transaction_pending() const noexcept
{
    return sqlite3_get_autocommit(handle.get()) == 0;
}

transaction connection::begin_transaction()
{
    begin_transaction_statement.reset();
    begin_transaction_statement.step();
    return transaction(*this);
}

statement connection::prepare(std::string_view sql)
{
    // SQLite takes the string length as an int for some reason, so check
    // if the length fits in an int.
    if(sql.size() > std::numeric_limits<int>::max()) {
        throw_error("SQL string too long");
    }
    sqlite3_stmt* stmt;
    const auto status = sqlite3_prepare_v2(handle.get(), sql.data(), static_cast<int>(sql.size()),
        &stmt, nullptr);
    if(status != SQLITE_OK) {
        throw_error(handle.get());
    }
    if(stmt == nullptr) {
        throw_error("no SQL in prepared statement");
    }
    return statement(stmt);
}

void connection::execute(std::string_view sql)
{
    prepare(sql).step();
}

auto connection::open(const char* file_name, open_mode mode) -> std::unique_ptr<sqlite3, deleter>
{
    initialize_sqlite();

    const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | mode_to_flags(mode);
    sqlite3* raw_connection;
    const auto status = sqlite3_open_v2(file_name, &raw_connection, flags, nullptr);
    std::unique_ptr<sqlite3, deleter> connection(raw_connection);

    if(connection == nullptr) {
        throw_error(status);
    }
    sqlite3_extended_result_codes(connection.get(), true);
    if(status == SQLITE_OK) {
        return connection;
    }
    throw_error(connection.get());
}

void connection::deleter::operator()(sqlite3* handle) const noexcept
{
    sqlite3_close(handle);
}


transaction::transaction(invalid_transaction_tag_) noexcept
    : parent(nullptr)
{
}

void transaction::commit()
{
    parent->commit_statement.reset();
    parent->commit_statement.step();
    // The commit succeeded, null out the connection pointer so that
    // our destructor doesn't attempt to rollback.
    static_cast<void>(parent.release());
}

bool transaction::valid() const noexcept
{
    return parent != nullptr;
}

transaction::transaction(connection& connection) noexcept
    : parent(&connection)
{
}

void transaction::deleter::operator()(connection* connection) const noexcept
{
    if(!connection->transaction_pending()) {
        // We're not in a transaction, it was rolled back automatically.
        return;
    }
    try {
        connection->rollback_statement.reset();
        connection->rollback_statement.step();
    } catch(const error&) {
        if(connection->transaction_pending()) {
            // Rollback failed and we're still in a transaction. There's no
            // way to fix things, so let std::terminate do its thing.
            std::terminate();
        }
    }
}

} // namespace filehash::sqlite
