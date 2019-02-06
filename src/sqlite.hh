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
#ifndef INCLUDED_1AD1113278EB42E28D1040FAAD63FF09
#define INCLUDED_1AD1113278EB42E28D1040FAAD63FF09
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <utility>

struct sqlite3;
struct sqlite3_stmt;

namespace filehash {

template <typename T>
class span;

namespace sqlite {

class error : public std::runtime_error {
public:
    explicit error(const char* message);
};

struct int_type_tag {
    using column_type = std::int64_t;
};

struct blob_type_tag {
    using column_type = span<const std::byte>;
};

struct string_type_tag {
    using column_type = std::string_view;
};

constexpr int_type_tag int_tag = {};
constexpr blob_type_tag blob_tag = {};
constexpr string_type_tag string_tag = {};

class statement;
template <typename... Tags>
class owning_cursor;

template <typename... Tags>
class row_cursor {
public:
    using row_type = std::tuple<typename Tags::column_type...>;

    std::optional<row_type> next();
private:
    friend class statement;
    friend class owning_cursor<Tags...>;

    explicit row_cursor(statement& stmt) noexcept;
    template <std::size_t... Idxs>
    row_type get_columns(std::index_sequence<Idxs...>);

    statement* parent;
};

class statement {
public:
    void reset() noexcept;
    bool step();
    // Note that blobs and strings must live at least until the call to step.
    void bind_one(int parameter_id, std::int64_t value);
    void bind_one(int parameter_id, span<const std::byte> value);
    void bind_one(int parameter_id, std::string_view value);
    template <typename... Args>
    void bind(Args&&... args);
    template <typename... Tags>
    row_cursor<Tags...> cursor(Tags...);
    template <typename... Tags>
    owning_cursor<Tags...> owning_cursor(Tags...) &&;
    template <typename... Tags>
    std::optional<typename row_cursor<Tags...>::row_type> get_single_row(Tags...);
    template <typename... Tags>
    typename row_cursor<Tags...>::row_type get_single_row_always(Tags...);
private:
    friend class connection;
    template <typename...>
    friend class row_cursor;
    template <typename...>
    friend class owning_cursor;

    explicit statement(sqlite3_stmt* statement) noexcept;

    [[noreturn]] static void throw_no_rows_error();
    void check_column_count(std::size_t column_count) const;

    // Note that the result for blobs and strings is only guaranteed to live
    // until the next call to reset and/or step.
    std::int64_t get(int column_id, int_type_tag) noexcept;
    span<const std::byte> get(int column_id, blob_type_tag);
    std::string_view get(int column_id, string_type_tag);

    template <typename... Args, std::size_t... Idxs>
    void bind_impl(std::index_sequence<Idxs...>, Args&&... args);

    struct deleter {
        void operator()(sqlite3_stmt* stmt) const noexcept;
    };
    std::unique_ptr<sqlite3_stmt, deleter> handle;
};

template <typename... Tags>
class owning_cursor {
public:
    using row_type = typename row_cursor<Tags...>::row_type;

    explicit owning_cursor(statement&& stmt);

    template <typename T>
    void bind_one(int parameter_id, T&& value);
    template <typename... Args>
    void bind(Args&&... args);
    void rewind() noexcept;
    std::optional<row_type> next();
private:
    statement stmt;
};

class transaction;

enum class open_mode {
    open_existing,
    create_new,
};

class connection {
public:
    explicit connection(const char* file_name, open_mode mode);

    void set_busy_timeout(int milliseconds);
    void set_chunk_size(int chunk_size, const char* database = nullptr);
    std::int64_t last_insert_rowid() const noexcept;
    int change_count() const noexcept;
    bool transaction_pending() const noexcept;
    [[nodiscard]] transaction begin_transaction();
    statement prepare(std::string_view sql);
    void execute(std::string_view sql);
private:
    friend class transaction;

    struct deleter {
        void operator()(sqlite3* handle) const noexcept;
    };

    static std::unique_ptr<sqlite3, deleter> open(const char* file_name, open_mode mode);

    std::unique_ptr<sqlite3, deleter> handle;
    statement begin_transaction_statement;
    statement commit_statement;
    statement rollback_statement;
};

struct invalid_transaction_tag_ {};
constexpr invalid_transaction_tag_ invalid_transaction_tag = {};

class transaction {
public:
    explicit transaction(invalid_transaction_tag_) noexcept;

    void commit();
    bool valid() const noexcept;
private:
    friend class connection;

    explicit transaction(connection& connection) noexcept;

    struct deleter {
        void operator()(connection* connection) const noexcept;
    };
    std::unique_ptr<connection, deleter> parent;
};


template <typename... Tags>
auto row_cursor<Tags...>::next() -> std::optional<row_type>
{
    return parent->step()
        ? std::optional(get_columns(std::make_index_sequence<sizeof...(Tags)>()))
        : std::nullopt;
}

template <typename... Tags>
row_cursor<Tags...>::row_cursor(statement& stmt) noexcept
    : parent(&stmt)
{
}

template <typename... Tags>
template <std::size_t... Idxs>
auto row_cursor<Tags...>::get_columns(std::index_sequence<Idxs...>) -> row_type
{
    return row_type(parent->get(Idxs, Tags{})...);
}


template <typename... Args>
void statement::bind(Args&&... args)
{
    bind_impl(std::make_index_sequence<sizeof...(Args)>(), std::forward<Args>(args)...);
}

template <typename... Tags>
row_cursor<Tags...> statement::cursor(Tags...)
{
    check_column_count(sizeof...(Tags));
    return row_cursor<Tags...>(*this);
}

template <typename ... Tags>
owning_cursor<Tags...> statement::owning_cursor(Tags...) &&
{
    return owning_cursor<Tags...>(std::move(*this));
}

template <typename... Tags>
std::optional<typename row_cursor<Tags...>::row_type> statement::get_single_row(Tags...)
{
    return cursor(Tags{}...).next();
}

template <typename... Tags>
typename row_cursor<Tags...>::row_type statement::get_single_row_always(Tags...)
{
    auto opt = get_single_row(Tags{}...);
    if(!opt) {
        throw_no_rows_error();
    }
    return *std::move(opt);
}

template <typename... Args, std::size_t... Idxs>
void statement::bind_impl(std::index_sequence<Idxs...>, Args&&... args)
{
    (..., bind_one(int{Idxs + 1}, std::forward<Args>(args)));
}


template <typename... Tags>
owning_cursor<Tags...>::owning_cursor(statement&& stmt)
    : stmt([&]{ stmt.check_column_count(sizeof...(Tags)); return std::move(stmt); }())
{
}

template <typename... Tags>
template <typename T>
void owning_cursor<Tags...>::bind_one(int parameter_id, T&& value)
{
    stmt.bind_one(parameter_id, std::forward<T>(value));
}

template <typename... Tags>
template <typename... Args>
void owning_cursor<Tags...>::bind(Args&&... args)
{
    stmt.bind(std::forward<Args>(args)...);
}

template <typename... Tags>
void owning_cursor<Tags...>::rewind() noexcept
{
    stmt.reset();
}

template <typename... Tags>
auto owning_cursor<Tags...>::next() -> std::optional<row_type>
{
    return row_cursor<Tags...>(stmt).next();
}

} // namespace filehash::sqlite
} // namespace filehash
#endif
