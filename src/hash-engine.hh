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
#ifndef INCLUDED_27C3A122CD174060B080B19B5E467A19
#define INCLUDED_27C3A122CD174060B080B19B5E467A19
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <string_view>
#include <string>
#include "blake2sp4.hh"
#include "file-watcher.hh"

namespace filehash {

template <typename T>
class span;

class file_descriptor;

namespace db {

class hash_inserter;

} // namespace db

class not_regular_file_error final : public std::exception {};

constexpr std::size_t chunk_size = 1048576;

class hash_engine {
public:
    explicit hash_engine(db::hash_inserter& inserter, std::mutex& output_mutex,
        std::ostream* verbose_output, std::ostream& error_output);

    void hash_file(const std::string& file_name);
private:
    void hash_file_loop(std::string_view file_name, file_descriptor& file,
        const file_watcher::watch& watch);
    void try_hash_file(file_descriptor& file, const file_watcher::watch& watch);
    void hash_contents(span<const std::byte> data);
    void save_current_chunk();
    void next_chunk() noexcept;
    void reset(file_descriptor& file);
    void try_detect_modifications(const file_watcher::watch& watch);

    std::unique_ptr<std::byte[]> buffer;
    db::hash_inserter* inserter;
    file_watcher watcher;
    blake2sp4 chunk_hash;
    blake2sp4 file_hash;
    std::size_t space_left_in_chunk;
    std::int64_t chunk_id;
    std::int64_t file_id;
    std::mutex* output_mutex;
    std::ostream* error_output;
    std::ostream* verbose_output;
};

} // namespace filehash
#endif
