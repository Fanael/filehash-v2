// Copyright 2019-2020 Fanael Linithien
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
#include <boost/hana/length.hpp>
#include <boost/hana/range.hpp>
#include <boost/hana/transform.hpp>
#include <boost/hana/tuple.hpp>
#include <boost/hana/type.hpp>
#include <boost/hana/unpack.hpp>
#include <boost/hana/zip_with.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/enum.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/transform.hpp>

struct sqlite3;
struct sqlite3_stmt;

namespace filehash {

template <typename T>
class span;

namespace sqlite {

class error : public std::runtime_error {
public:
    explicit error(int code, const char* message);
    explicit error(int code, const std::string& message);

    int code() const noexcept;
    const char* code_message() const noexcept;
private:
    int error_code;
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

decltype(boost::hana::tuple_t<int_column_tag>) row_type_column_tags_(std::int64_t&&);
decltype(boost::hana::tuple_t<blob_column_tag>) row_type_column_tags_(span<const std::byte>&&);
decltype(boost::hana::tuple_t<string_column_tag>) row_type_column_tags_(std::string_view&&);
decltype(boost::hana::tuple_t<nullable_int_column_tag>) row_type_column_tags_(
    std::optional<std::int64_t>&&);

template <typename T>
typename T::row_type_column_tags row_type_column_tags_(T&&);

template <typename RowType>
constexpr auto row_type_column_tags = decltype(row_type_column_tags_(std::declval<RowType&&>()))();

// NB: maybe_unused to silence some spurious GCC warnings.
#define FILEHASH_SQLITE_REGISTER_ROW_TYPE(...)\
    using row_type_column_tags [[maybe_unused]] = decltype(::boost::hana::tuple_t<__VA_ARGS__>)

#define FILEHASH_SQLITE_DEFINE_ROW_TYPE(columns_seq)\
    FILEHASH_SQLITE_DEFINE_ROW_TYPE_COLUMNS(columns_seq)\
    FILEHASH_SQLITE_REGISTER_ROW_TYPE(BOOST_PP_SEQ_ENUM(\
        BOOST_PP_SEQ_TRANSFORM(FILEHASH_SQLITE_ROW_TYPE_COLUMN_TAG, _, columns_seq)))

#define FILEHASH_SQLITE_ROW_TYPE_COLUMN_TAG(_d, _x, column_seq) BOOST_PP_SEQ_ELEM(0, column_seq)

#define FILEHASH_SQLITE_DEFINE_ROW_TYPE_COLUMNS(columns_seq)\
    BOOST_PP_SEQ_FOR_EACH(FILEHASH_SQLITE_DEFINE_ROW_TYPE_COLUMN, _, columns_seq)

#define FILEHASH_SQLITE_DEFINE_ROW_TYPE_COLUMN(_r, _x, column_seq)\
    BOOST_PP_SEQ_ELEM(0, column_seq)::column_type BOOST_PP_SEQ_ELEM(1, column_seq);

class statement;
template <typename RowType>
class owning_cursor;

template <typename RowType>
class row_cursor {
public:
    explicit row_cursor(statement& stmt);

    std::optional<RowType> next();
private:
    friend class owning_cursor<RowType>;

    struct unchecked_tag {};
    explicit row_cursor(statement& stmt, unchecked_tag) noexcept;

    statement* parent;
};

class statement {
public:
    bool is_moved_from() const noexcept;

    void reset() noexcept;
    bool step();
    // Note that blobs and strings must live at least until the call to step.
    void bind_one(int parameter_id, std::int64_t value);
    void bind_one(int parameter_id, span<const std::byte> value);
    void bind_one(int parameter_id, std::string_view value);
    template <typename... Args>
    void bind(Args&&... args);

    template <typename RowType>
    std::optional<RowType> get_single_row();
    template <typename RowType>
    RowType get_single_row_always();
private:
    friend class connection;
    template <typename>
    friend class row_cursor;
    template <typename>
    friend class owning_cursor;

    explicit statement(sqlite3_stmt* statement) noexcept;

    [[noreturn]] void throw_step_error(int error_code);
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

template <typename RowType>
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

template <typename RowType>
class restricted_owning_cursor : private owning_cursor<RowType> {
public:
    using owning_cursor<RowType>::owning_cursor;
    using owning_cursor<RowType>::rewind;
    using owning_cursor<RowType>::next;
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


template <typename RowType>
row_cursor<RowType>::row_cursor(statement& stmt)
    : parent([&] {
        stmt.check_column_count(boost::hana::length(row_type_column_tags<RowType>));
        return &stmt;
    }())
{
}

template <typename RowType>
std::optional<RowType> row_cursor<RowType>::next()
{
    if(!parent->step()) {
        return std::nullopt;
    }

    namespace hana = boost::hana;
    constexpr auto column_tags = row_type_column_tags<RowType>;
    // Get the raw values of each column first.
    const auto get_row = [&](const auto& index, auto raw_tag) {
        return parent->get(index.value, typename decltype(raw_tag)::type{});
    };
    auto raw_column_values = hana::zip_with(get_row,
        hana::to_tuple(hana::range_c<std::size_t, 0, hana::length(column_tags)>),
        hana::transform(column_tags,
            [](auto tag) { return hana::type_c<typename decltype(tag)::type::raw_tag>; }));
    // Apply the transformer if one exists, otherwise return the column value
    // unchanged.
    constexpr auto has_transform = hana::is_valid(
        [](auto tag) -> decltype(static_cast<void>(&decltype(tag)::type::transform)) {});
    const auto transform_column = [](auto tag, auto&& arg) {
        return decltype(tag)::type::transform(std::forward<decltype(arg)>(arg));
    };
    const auto transform_column_if_needed = [&](auto tag, auto&& value) {
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

template <typename RowType>
row_cursor<RowType>::row_cursor(statement& stmt, unchecked_tag) noexcept
    : parent(&stmt)
{
}


template <typename... Args>
void statement::bind(Args&&... args)
{
    bind_impl(std::make_index_sequence<sizeof...(Args)>(), std::forward<Args>(args)...);
}

template <typename RowType>
std::optional<RowType> statement::get_single_row()
{
    return row_cursor<RowType>(*this).next();
}

template <typename RowType>
RowType statement::get_single_row_always()
{
    auto row = get_single_row<RowType>();
    if(!row) {
        throw_no_rows_error();
    }
    return *std::move(row);
}

template <typename... Args, std::size_t... Idxs>
void statement::bind_impl(std::index_sequence<Idxs...>, Args&&... args)
{
    (..., bind_one(int{Idxs + 1}, std::forward<Args>(args)));
}


template <typename RowType>
owning_cursor<RowType>::owning_cursor(statement&& stmt)
    : stmt([&]{
        stmt.check_column_count(boost::hana::length(row_type_column_tags<RowType>));
        return std::move(stmt);
    }())
{
}

template <typename RowType>
template <typename T>
void owning_cursor<RowType>::bind_one(int parameter_id, T&& value)
{
    stmt.bind_one(parameter_id, std::forward<T>(value));
}

template <typename RowType>
template <typename... Args>
void owning_cursor<RowType>::bind(Args&&... args)
{
    stmt.bind(std::forward<Args>(args)...);
}

template <typename RowType>
void owning_cursor<RowType>::rewind() noexcept
{
    stmt.reset();
}

template <typename RowType>
std::optional<RowType> owning_cursor<RowType>::next()
{
    return row_cursor<RowType>(stmt, typename row_cursor<RowType>::unchecked_tag{}).next();
}

} // namespace filehash::sqlite
} // namespace filehash
#endif
