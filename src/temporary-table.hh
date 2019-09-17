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
#ifndef INCLUDED_CD9B4C6F6C274AB2A2F8D3691CCF4972
#define INCLUDED_CD9B4C6F6C274AB2A2F8D3691CCF4972
#include <string_view>
#include "sqlite.hh"

namespace filehash::sqlite {

class temporary_table_guard {
public:
    ~temporary_table_guard() noexcept;
    temporary_table_guard(temporary_table_guard&& other) noexcept = default;
    temporary_table_guard(const temporary_table_guard&) = delete;
    temporary_table_guard& operator=(const temporary_table_guard&) = delete;
    temporary_table_guard& operator=(temporary_table_guard&&) = delete;
private:
    friend temporary_table_guard make_temporary_table(sqlite::connection& connection,
        std::string_view create_sql, std::string_view drop_sql);

    explicit temporary_table_guard(sqlite::statement drop_table) noexcept;

    sqlite::statement drop_table_statement;
};

temporary_table_guard make_temporary_table(sqlite::connection& connection,
    std::string_view create_sql, std::string_view drop_sql);

} // namespace filehash::sqlite
#endif
