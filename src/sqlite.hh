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
#include <utility>
#include <boost/hana/functional/arg.hpp>
#include <boost/hana/if.hpp>
#include <boost/hana/range.hpp>
#include <boost/hana/transform.hpp>
#include <boost/hana/tuple.hpp>
#include <boost/hana/type.hpp>
#include <boost/hana/unpack.hpp>
#include <boost/hana/zip_with.hpp>

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

template <typename ColumnType>
struct basic_column_tag {
    using raw_tag = basic_column_tag;
    using column_type = ColumnType;
};

using int_column_tag =  basic_column_tag<std::int64_t>;
using blob_column_tag = basic_column_tag<span<const std::byte>>;
using string_column_tag = basic_column_tag<std::string_view>;
using nullable_int_column_tag = basic_column_tag<std::optional<std::int64_t>>;

class statement;
template <typename RowType, typename... ColumnTags>
class owning_cursor;

template <typename RowType, typename... ColumnTags>
class row_cursor {
public:
    explicit row_cursor(statement& stmt);

    std::optional<RowType> next();
    RowType next_always();
private:
    friend class owning_cursor<RowType, ColumnTags...>;

    struct unchecked_tag {};
    explicit row_cursor(statement& stmt, unchecked_tag) noexcept;

    statement* parent;
};

template <typename ColumnTag>
using single_column_cursor = row_cursor<typename ColumnTag::column_type, ColumnTag>;

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
private:
    friend class connection;
    template <typename, typename...>
    friend class row_cursor;
    template <typename, typename...>
    friend class owning_cursor;

    explicit statement(sqlite3_stmt* statement) noexcept;

    [[noreturn]] static void throw_no_rows_error();
    void check_column_count(std::size_t column_count) const;

    // Note that the result for blobs and strings is only guaranteed to live
    // until the next call to reset and/or step.
    std::int64_t get(int column_id, int_column_tag);
    std::optional<std::int64_t> get(int column_id, nullable_int_column_tag) noexcept;
    span<const std::byte> get(int column_id, blob_column_tag);
    std::string_view get(int column_id, string_column_tag);

    template <typename... Args, std::size_t... Idxs>
    void bind_impl(std::index_sequence<Idxs...>, Args&&... args);

    struct deleter {
        void operator()(sqlite3_stmt* stmt) const noexcept;
    };
    std::unique_ptr<sqlite3_stmt, deleter> handle;
};

template <typename RowType, typename... ColumnTags>
class owning_cursor {
public:
    explicit owning_cursor(statement&& stmt);

    template <typename T>
    void bind_one(int parameter_id, T&& value);
    template <typename... Args>
    void bind(Args&&... args);
    void rewind() noexcept;
    std::optional<RowType> next();
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


template <typename RowType, typename... ColumnTags>
row_cursor<RowType, ColumnTags...>::row_cursor(statement& stmt)
    : parent([&] { stmt.check_column_count(sizeof...(ColumnTags)); return &stmt; }())
{
}

template <typename RowType, typename... ColumnTags>
std::optional<RowType> row_cursor<RowType, ColumnTags...>::next()
{
    if(!parent->step()) {
        return std::nullopt;
    }

    namespace hana = boost::hana;
    constexpr auto column_tags = hana::tuple_t<ColumnTags...>;
    // Get the raw values of each column first.
    const auto get_row = [&](const auto& index, const auto& raw_tag_type) {
        return parent->get(index.value, typename decltype(+raw_tag_type)::type{});
    };
    auto raw_column_values = hana::zip_with(get_row,
        hana::to_tuple(hana::range_c<std::size_t, 0, sizeof...(ColumnTags)>),
        hana::transform(column_tags,
            [](const auto& tag) {return hana::type_c<typename decltype(+tag)::type::raw_tag>;}));
    // Apply the transformer if one exists, otherwise return the column value
    // unchanged.
    constexpr auto has_transform = hana::is_valid(
        [](const auto& tag) -> decltype(static_cast<void>(&decltype(+tag)::type::transform)) {});
    const auto transform_column = [](const auto& tag, auto&& arg) {
        return decltype(+tag)::type::transform(std::forward<decltype(arg)>(arg));
    };
    const auto transform_column_if_needed = [&](const auto& tag, auto&& value) {
        return hana::if_(has_transform(tag), transform_column, hana::arg<2>)(
            tag, std::forward<decltype(value)>(value));
    };
    auto transformed_values = hana::zip_with(transform_column_if_needed, column_tags,
        std::move(raw_column_values));
    // Transformation went well, we can return the row.
    return std::optional(hana::unpack(std::move(transformed_values), [](auto&&... args) -> RowType {
        return RowType{std::forward<decltype(args)>(args)...};
    }));
}

template <typename RowType, typename... ColumnTags>
RowType row_cursor<RowType, ColumnTags...>::next_always()
{
    auto row = next();
    if(!row) {
        parent->throw_no_rows_error();
    }
    return *std::move(row);
}

template <typename RowType, typename... ColumnTags>
row_cursor<RowType, ColumnTags...>::row_cursor(statement& stmt, unchecked_tag) noexcept
    : parent(&stmt)
{
}


template <typename... Args>
void statement::bind(Args&&... args)
{
    bind_impl(std::make_index_sequence<sizeof...(Args)>(), std::forward<Args>(args)...);
}

template <typename... Args, std::size_t... Idxs>
void statement::bind_impl(std::index_sequence<Idxs...>, Args&&... args)
{
    (..., bind_one(int{Idxs + 1}, std::forward<Args>(args)));
}


template <typename RowType, typename... ColumnTags>
owning_cursor<RowType, ColumnTags...>::owning_cursor(statement&& stmt)
    : stmt([&]{ stmt.check_column_count(sizeof...(ColumnTags)); return std::move(stmt); }())
{
}

template <typename RowType, typename... ColumnTags>
template <typename T>
void owning_cursor<RowType, ColumnTags...>::bind_one(int parameter_id, T&& value)
{
    stmt.bind_one(parameter_id, std::forward<T>(value));
}

template <typename RowType, typename... ColumnTags>
template <typename... Args>
void owning_cursor<RowType, ColumnTags...>::bind(Args&&... args)
{
    stmt.bind(std::forward<Args>(args)...);
}

template <typename RowType, typename... ColumnTags>
void owning_cursor<RowType, ColumnTags...>::rewind() noexcept
{
    stmt.reset();
}

template <typename RowType, typename... ColumnTags>
std::optional<RowType> owning_cursor<RowType, ColumnTags...>::next()
{
    using cursor_impl = row_cursor<RowType, ColumnTags...>;
    return cursor_impl(stmt, typename cursor_impl::unchecked_tag{}).next();
}

} // namespace filehash::sqlite
} // namespace filehash
#endif
