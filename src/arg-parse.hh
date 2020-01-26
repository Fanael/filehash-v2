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
#ifndef INCLUDED_E95D8250806B4887B9909FCA50E109AC
#define INCLUDED_E95D8250806B4887B9909FCA50E109AC
#include <cstddef>
#include <exception>
#include <iosfwd>
#include <string_view>
#include <variant>
#include "span.hh"

namespace filehash {

namespace args {

class command_cookie {
public:
    constexpr command_cookie() noexcept;
    constexpr explicit command_cookie(std::size_t id) noexcept;
    constexpr std::size_t get() const noexcept;
    constexpr bool valid() const noexcept;
private:
    std::size_t id;
};

class parse_error : public std::exception {
public:
    const char* what() const noexcept override;
    virtual command_cookie command() const noexcept = 0;
private:
    virtual void print(std::ostream& stream) const = 0;

    friend std::ostream& operator<<(std::ostream& stream, const parse_error& error);
};

struct usage {
public:
    constexpr explicit usage(command_cookie cookie, std::string_view program_name) noexcept;
private:
    command_cookie cookie;
    std::string_view program_name;

    friend std::ostream& operator<<(std::ostream& stream, const usage& u);
};

struct diff_command {
    std::string_view database_path;
    std::string_view old_snapshot_name;
    std::string_view new_snapshot_name;
};

struct fsck_command {
    std::string_view database_path;
};

struct full_diff_command {
    std::string_view database_path;
};

struct gc_command {
    std::string_view database_path;
};

struct help_command {
    command_cookie cookie;
};

struct init_command {
    std::string_view database_path;
};

struct list_command {
    std::string_view database_path;
};

struct new_command {
    std::string_view database_path;
    std::string_view snapshot_name;
};

struct new_empty_command {
    std::string_view database_path;
    std::string_view snapshot_name;
};

struct remove_command {
    std::string_view database_path;
    span<const std::string_view> snapshot_names;
};

struct update_command {
    std::string_view database_path;
    std::string_view snapshot_name;
};

using command = std::variant<
    diff_command,
    fsck_command,
    full_diff_command,
    gc_command,
    help_command,
    init_command,
    list_command,
    new_command,
    new_empty_command,
    remove_command,
    update_command>;

struct common_args {
    std::size_t thread_count = 0;
    bool verbose = false;
    bool use_watcher = true;
};

struct args {
    common_args common;
    command cmd;
};

args parse_args(span<const std::string_view> args);


constexpr usage::usage(command_cookie cookie, std::string_view program_name) noexcept
    : cookie(cookie), program_name(program_name)
{
}

} // namespace filehash::args
} // namespace filehash
#endif
