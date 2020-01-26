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
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <boost/endian/conversion.hpp>
#include "blake2sp4.hh"
#include "span.hh"
#ifdef __SSE2__
# include <immintrin.h>
#endif

namespace filehash {
namespace {

constexpr std::size_t state_words = 8;

constexpr std::array<std::uint32_t, state_words> initial_state = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

constexpr std::array<std::array<unsigned char, 16>, 10> sigma = {{
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
}};

constexpr std::uint32_t depth = 2;
constexpr std::uint32_t output_bytes = std::tuple_size_v<blake2sp4::result_type>;

constexpr void initialize_root_parameters(std::array<std::uint32_t, state_words>& state,
    std::uint32_t fanout) noexcept
{
    state[0] ^= output_bytes | (fanout << 16) | (depth << 24);
    state[4] ^= (UINT32_C(1) << 16) | (output_bytes << 24);
}

constexpr void initialize_leaf_parameters(std::array<std::uint32_t, state_words>& state,
    std::uint32_t fanout, std::uint32_t leaf_offset) noexcept
{
    state[0] ^= output_bytes | (fanout << 16) | (depth << 24);
    state[2] ^= leaf_offset;
}

// NB: The critical functions are marked inline to increase the compiler's
// keenness to actually inline them - Clang and GCC at the very least do
// use inline in such a way.

constexpr inline std::uint32_t rotate_right(std::uint32_t value, unsigned amount) noexcept
{
    return (value >> amount) | (value << (-amount % 32));
}

constexpr inline void blake2s_g(std::array<std::uint32_t, 16>& state, unsigned a, unsigned b,
    unsigned c, unsigned d, std::uint32_t x, std::uint32_t y) noexcept
{
    state[a] += state[b] + x;
    state[d] = rotate_right(state[d] ^ state[a], 16);
    state[c] += state[d];
    state[b] = rotate_right(state[b] ^ state[c], 12);
    state[a] += state[b] + y;
    state[d] = rotate_right(state[d] ^ state[a], 8);
    state[c] += state[d];
    state[b] = rotate_right(state[b] ^ state[c], 7);
}

void blake2s_f(std::array<std::uint32_t, state_words>& hash_state,
    const std::uint32_t* message_block, std::uint64_t byte_counter, bool is_final_block) noexcept
{
    std::array<std::uint32_t, 16> mix_state;

    std::copy(hash_state.cbegin(), hash_state.cend(), mix_state.begin());
    std::copy(initial_state.cbegin(), initial_state.cend(), mix_state.begin() + state_words);

    mix_state[12] ^= static_cast<std::uint32_t>(byte_counter & UINT32_MAX);
    mix_state[13] ^= static_cast<std::uint32_t>(byte_counter >> 32);

    if(is_final_block) {
        mix_state[14] = ~mix_state[14];
    }

    for(const auto& s: sigma) {
        blake2s_g(mix_state, 0, 4,  8, 12, message_block[s[ 0]], message_block[s[ 1]]);
        blake2s_g(mix_state, 1, 5,  9, 13, message_block[s[ 2]], message_block[s[ 3]]);
        blake2s_g(mix_state, 2, 6, 10, 14, message_block[s[ 4]], message_block[s[ 5]]);
        blake2s_g(mix_state, 3, 7, 11, 15, message_block[s[ 6]], message_block[s[ 7]]);

        blake2s_g(mix_state, 0, 5, 10, 15, message_block[s[ 8]], message_block[s[ 9]]);
        blake2s_g(mix_state, 1, 6, 11, 12, message_block[s[10]], message_block[s[11]]);
        blake2s_g(mix_state, 2, 7,  8, 13, message_block[s[12]], message_block[s[13]]);
        blake2s_g(mix_state, 3, 4,  9, 14, message_block[s[14]], message_block[s[15]]);
    }

    for(unsigned i = 0; i < state_words; ++i) {
        hash_state[i] ^= mix_state[i] ^ mix_state[i + state_words];
    }
}

template <std::size_t N>
inline void array_to_little_endian(std::array<std::uint32_t, N>& array) noexcept
{
    for(auto& word: array) {
        word = boost::endian::native_to_little(word);
    }
}

#ifdef __SSE2__
inline __m128i rotate_right(__m128i value, unsigned amount) noexcept
{
    return _mm_or_si128(_mm_srli_epi32(value, amount % 32), _mm_slli_epi32(value, -amount % 32));
}

inline void blake2s_g_vector(__m128i& a, __m128i& b, __m128i& c, __m128i& d, __m128i x,
    __m128i y) noexcept
{
#ifdef __SSSE3__
    const auto rot16_shuffle = _mm_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
    const auto rot8_shuffle = _mm_setr_epi8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
#endif

    a = _mm_add_epi32(a, x);
    a = _mm_add_epi32(a, b);
    d = _mm_xor_si128(d, a);
#ifdef __SSSE3__
    d = _mm_shuffle_epi8(d, rot16_shuffle);
#else
    d = rotate_right(d, 16);
#endif
    c = _mm_add_epi32(c, d);
    b = _mm_xor_si128(b, c);
    b = rotate_right(b, 12);
    a = _mm_add_epi32(a, y);
    a = _mm_add_epi32(a, b);
    d = _mm_xor_si128(d, a);
#ifdef __SSSE3__
    d = _mm_shuffle_epi8(d, rot8_shuffle);
#else
    d = rotate_right(d, 8);
#endif
    c = _mm_add_epi32(c, d);
    b = _mm_xor_si128(b, c);
    b = rotate_right(b, 7);
}

inline void blake2s_f_vector(std::array<std::uint32_t, 32>& hash_state,
    const std::array<std::uint32_t, 64>& message_block,
    const std::array<std::uint32_t, 8>& byte_counters) noexcept
{
    auto hash_0 = _mm_load_si128(reinterpret_cast<const __m128i*>(&hash_state[ 0]));
    auto hash_1 = _mm_load_si128(reinterpret_cast<const __m128i*>(&hash_state[ 4]));
    auto hash_2 = _mm_load_si128(reinterpret_cast<const __m128i*>(&hash_state[ 8]));
    auto hash_3 = _mm_load_si128(reinterpret_cast<const __m128i*>(&hash_state[12]));
    auto hash_4 = _mm_load_si128(reinterpret_cast<const __m128i*>(&hash_state[16]));
    auto hash_5 = _mm_load_si128(reinterpret_cast<const __m128i*>(&hash_state[20]));
    auto hash_6 = _mm_load_si128(reinterpret_cast<const __m128i*>(&hash_state[24]));
    auto hash_7 = _mm_load_si128(reinterpret_cast<const __m128i*>(&hash_state[28]));

    auto w_0 = hash_0;
    auto w_1 = hash_1;
    auto w_2 = hash_2;
    auto w_3 = hash_3;
    auto w_4 = hash_4;
    auto w_5 = hash_5;
    auto w_6 = hash_6;
    auto w_7 = hash_7;
    auto w_8 = _mm_set1_epi32(static_cast<std::int32_t>(initial_state[0]));
    auto w_9 = _mm_set1_epi32(static_cast<std::int32_t>(initial_state[1]));
    auto w10 = _mm_set1_epi32(static_cast<std::int32_t>(initial_state[2]));
    auto w11 = _mm_set1_epi32(static_cast<std::int32_t>(initial_state[3]));
    auto w12 = _mm_set1_epi32(static_cast<std::int32_t>(initial_state[4]));
    auto w13 = _mm_set1_epi32(static_cast<std::int32_t>(initial_state[5]));
    auto w14 = _mm_set1_epi32(static_cast<std::int32_t>(initial_state[6]));
    auto w15 = _mm_set1_epi32(static_cast<std::int32_t>(initial_state[7]));

    w12 = _mm_xor_si128(w12, _mm_load_si128(reinterpret_cast<const __m128i*>(&byte_counters[0])));
    w13 = _mm_xor_si128(w13, _mm_load_si128(reinterpret_cast<const __m128i*>(&byte_counters[4])));
    const auto msg = reinterpret_cast<const __m128i*>(&message_block[0]);
    for(const auto& s: sigma) {
        blake2s_g_vector(w_0, w_4, w_8, w12, msg[s[ 0]], msg[s[ 1]]);
        blake2s_g_vector(w_1, w_5, w_9, w13, msg[s[ 2]], msg[s[ 3]]);
        blake2s_g_vector(w_2, w_6, w10, w14, msg[s[ 4]], msg[s[ 5]]);
        blake2s_g_vector(w_3, w_7, w11, w15, msg[s[ 6]], msg[s[ 7]]);

        blake2s_g_vector(w_0, w_5, w10, w15, msg[s[ 8]], msg[s[ 9]]);
        blake2s_g_vector(w_1, w_6, w11, w12, msg[s[10]], msg[s[11]]);
        blake2s_g_vector(w_2, w_7, w_8, w13, msg[s[12]], msg[s[13]]);
        blake2s_g_vector(w_3, w_4, w_9, w14, msg[s[14]], msg[s[15]]);
    }

    hash_0 = _mm_xor_si128(hash_0, _mm_xor_si128(w_0, w_8));
    hash_1 = _mm_xor_si128(hash_1, _mm_xor_si128(w_1, w_9));
    hash_2 = _mm_xor_si128(hash_2, _mm_xor_si128(w_2, w10));
    hash_3 = _mm_xor_si128(hash_3, _mm_xor_si128(w_3, w11));
    hash_4 = _mm_xor_si128(hash_4, _mm_xor_si128(w_4, w12));
    hash_5 = _mm_xor_si128(hash_5, _mm_xor_si128(w_5, w13));
    hash_6 = _mm_xor_si128(hash_6, _mm_xor_si128(w_6, w14));
    hash_7 = _mm_xor_si128(hash_7, _mm_xor_si128(w_7, w15));

    _mm_store_si128(reinterpret_cast<__m128i*>(&hash_state[ 0]), hash_0);
    _mm_store_si128(reinterpret_cast<__m128i*>(&hash_state[ 4]), hash_1);
    _mm_store_si128(reinterpret_cast<__m128i*>(&hash_state[ 8]), hash_2);
    _mm_store_si128(reinterpret_cast<__m128i*>(&hash_state[12]), hash_3);
    _mm_store_si128(reinterpret_cast<__m128i*>(&hash_state[16]), hash_4);
    _mm_store_si128(reinterpret_cast<__m128i*>(&hash_state[20]), hash_5);
    _mm_store_si128(reinterpret_cast<__m128i*>(&hash_state[24]), hash_6);
    _mm_store_si128(reinterpret_cast<__m128i*>(&hash_state[28]), hash_7);
}
#endif

} // unnamed namespace

blake2sp4::blake2sp4() noexcept
{
    reset();
}

void blake2sp4::reset() noexcept
{
    buffer_byte_position = 0;

    for(std::size_t i = 0; i < leaf_states.size(); ++i) {
        leaf_states[i].words = initial_state;
        leaf_states[i].total_byte_count = 0;
        initialize_leaf_parameters(leaf_states[i].words, parallelism_degree,
            static_cast<std::uint32_t>(i));
    }
}

void blake2sp4::update(span<const std::byte> bytes) noexcept
{
    for(;;) {
        const auto free_space = buffer_free_space();
        const auto fitting_in_buffer = bytes.first(free_space.size());
        bytes = bytes.drop_first(free_space.size());
        std::memmove(free_space.data(), fitting_in_buffer.data(), fitting_in_buffer.size_bytes());
        buffer_byte_position += fitting_in_buffer.size();
        if(bytes.empty()) {
            break;
        }
        // We still have bytes remaining, mix the buffer and try again.
        array_to_little_endian(buffer);
        mix_buffer();
        buffer_byte_position = 0;
    }
}

auto blake2sp4::finalize() noexcept -> result_type
{
    std::array<std::uint32_t, state_words * parallelism_degree> leaf_buffer;
    for(std::size_t i = 0; i < parallelism_degree; ++i) {
        auto& leaf = leaf_states[i];
        if(buffer_byte_position > i * block_bytes) {
            const auto bytes_left = std::min(buffer_byte_position - i * block_bytes, block_bytes);
            const auto bytes_to_zero = block_bytes - bytes_left;
            const auto zeros_start =
                reinterpret_cast<std::byte*>(buffer.data()) + buffer_byte_position;
            const auto data_start = buffer.data() + i * block_words;
            std::memset(zeros_start, 0, bytes_to_zero);
            leaf.total_byte_count += bytes_left;
            blake2s_f(leaf.words, data_start, leaf.total_byte_count, true);
        } else {
            // NB: slight difference in behavior from the official version in
            // that we already processed what turned out to be the last block
            // with the last block flag set to false, so we can't go back in
            // time to process it with that flag set to true. Instead, finalize
            // the hash by processing a block of zeros, with the same byte
            // count as last time, but with last block flag set to true.
            static constexpr std::uint32_t zeros[block_words] = {};
            blake2s_f(leaf.words, zeros, leaf.total_byte_count, true);
        }

        std::copy(leaf.words.cbegin(), leaf.words.cend(), leaf_buffer.begin() + state_words * i);
    }

    state root_state;
    root_state.words = initial_state;
    root_state.total_byte_count = 0;
    initialize_root_parameters(root_state.words, parallelism_degree);
    static_assert(leaf_buffer.size() % block_words == 0);
    array_to_little_endian(leaf_buffer);
    const auto leaf_buffer_blocks = leaf_buffer.size() / block_words;
    for(std::size_t i = 0; i < leaf_buffer_blocks; ++i) {
        blake2s_f(root_state.words, leaf_buffer.data() + i * block_words, (i + 1) * block_bytes,
            i == leaf_buffer_blocks - 1);
    }
    result_type result;
    std::memcpy(result.data(), root_state.words.data(), result.size());
    return result;
}

inline span<std::byte> blake2sp4::buffer_free_space() noexcept
{
    return span(reinterpret_cast<std::byte*>(buffer.data()) + buffer_byte_position,
        reinterpret_cast<std::byte*>(buffer.data() + buffer.size()));
}

void blake2sp4::mix_buffer() noexcept
{
#ifdef __SSE2__
    for(auto& leaf: leaf_states) {
        leaf.total_byte_count += block_bytes;
    }
    // These transpositions could be hand optimized, but GCC and Clang generate
    // decent code already.
    static_assert(parallelism_degree == 4,
        "SSE2 code assumes that parallelism degree is exactly 4");
    alignas(16) std::array<std::uint32_t, block_words * parallelism_degree> transposed_buffer;
    for(std::size_t i = 0; i < block_words; ++i) {
        transposed_buffer[parallelism_degree * i + 0] = buffer[i + block_words * 0];
        transposed_buffer[parallelism_degree * i + 1] = buffer[i + block_words * 1];
        transposed_buffer[parallelism_degree * i + 2] = buffer[i + block_words * 2];
        transposed_buffer[parallelism_degree * i + 3] = buffer[i + block_words * 3];
    }
    alignas(16) std::array<std::uint32_t, 8 * parallelism_degree> transposed_state;
    for(std::size_t i = 0; i < 8; ++i) {
        transposed_state[parallelism_degree * i + 0] = leaf_states[0].words[i];
        transposed_state[parallelism_degree * i + 1] = leaf_states[1].words[i];
        transposed_state[parallelism_degree * i + 2] = leaf_states[2].words[i];
        transposed_state[parallelism_degree * i + 3] = leaf_states[3].words[i];
    }
    alignas(16) std::array<std::uint32_t, 2 * parallelism_degree> byte_counts;
    for(std::size_t i = 0; i < parallelism_degree; ++i) {
        byte_counts[i] = static_cast<std::uint32_t>(leaf_states[i].total_byte_count & UINT32_MAX);
        byte_counts[parallelism_degree + i] =
            static_cast<std::uint32_t>(leaf_states[i].total_byte_count >> 32);
    }

    blake2s_f_vector(transposed_state, transposed_buffer, byte_counts);

    for(std::size_t i = 0; i < 8; ++i) {
        leaf_states[0].words[i] = transposed_state[parallelism_degree * i + 0];
        leaf_states[1].words[i] = transposed_state[parallelism_degree * i + 1];
        leaf_states[2].words[i] = transposed_state[parallelism_degree * i + 2];
        leaf_states[3].words[i] = transposed_state[parallelism_degree * i + 3];
    }
#else
    for(std::size_t i = 0; i < parallelism_degree; ++i) {
        auto& leaf = leaf_states[i];
        leaf.total_byte_count += block_bytes;
        blake2s_f(leaf.words, &buffer[i * block_words], leaf.total_byte_count, false);
    }
#endif
}

} // namespace filehash
