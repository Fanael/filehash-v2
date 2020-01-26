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
#ifndef INCLUDED_12D4659F489843B3B0B56F5B2D946597
#define INCLUDED_12D4659F489843B3B0B56F5B2D946597
#include <array>
#include <cstddef>
#include <cstdint>

namespace filehash {

template <typename T>
class span;

class blake2sp4 {
public:
    using result_type = std::array<std::byte, 32>;

    blake2sp4() noexcept;
    void reset() noexcept;
    void update(span<const std::byte> bytes) noexcept;
    result_type finalize() noexcept;
private:
    static constexpr std::size_t parallelism_degree = 4;
    static constexpr std::size_t block_words = 16;
    static constexpr std::size_t block_bytes = block_words * sizeof(std::uint32_t);

    struct state {
        std::array<std::uint32_t, 8> words;
        std::uint64_t total_byte_count;
    };

    span<std::byte> buffer_free_space() noexcept;
    void mix_buffer() noexcept;

    std::array<state, parallelism_degree> leaf_states;
    std::array<std::uint32_t, parallelism_degree * block_words> buffer;
    std::size_t buffer_byte_position;
};

} // namespace filehash
#endif
