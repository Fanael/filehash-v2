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
#include <utility>
#include "temporary-table.hh"

namespace filehash::sqlite {

temporary_table_guard::~temporary_table_guard() noexcept
{
    if(drop_table_statement.is_moved_from()) {
        return;
    }
    drop_table_statement.reset();
    // We're fine with aborting if this fails, because it means something
    // went seriously wrong.
    drop_table_statement.step();
}

temporary_table_guard::temporary_table_guard(sqlite::statement drop_table) noexcept
    : drop_table_statement(std::move(drop_table))
{
}

temporary_table_guard make_temporary_table(sqlite::connection& connection,
    std::string_view create_sql, std::string_view drop_sql)
{
    connection.execute(create_sql);
    return temporary_table_guard(connection.prepare(drop_sql));
}

} // namespace filehash::sqlite
