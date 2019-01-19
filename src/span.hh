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
#ifndef INCLUDED_2A5C758EAE9D4DC292BD22109C7DD444
#define INCLUDED_2A5C758EAE9D4DC292BD22109C7DD444
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <memory>

namespace filehash {

template <typename T>
class span {
public:
    using element_type = T;
    using value_type = std::remove_cv_t<T>;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using reference = T&;
    using iterator = T*;
    using const_iterator = const T*;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    constexpr span() noexcept = default;
    constexpr span(T* begin, T* end) noexcept;
    constexpr span(T* begin, std::size_t size) noexcept;
    template <typename U, typename = std::enable_if_t<
        std::is_convertible_v<
            std::remove_pointer_t<decltype(std::data(std::declval<U&>()))> (*)[],
            T (*)[]>
        && !std::is_same_v<span, std::remove_cv_t<std::remove_reference_t<U>>>>>
    constexpr /*implicit*/ span(U& container);
    template <typename U, typename = std::enable_if_t<
        std::is_convertible_v<U (*)[], T (*)[]>
        && !std::is_same_v<T, U>>>
    constexpr /*implicit*/ span(span<U> other) noexcept;

    constexpr iterator begin() const noexcept;
    constexpr iterator end() const noexcept;
    constexpr const_iterator cbegin() const noexcept;
    constexpr const_iterator cend() const noexcept;
    constexpr reverse_iterator rbegin() const noexcept;
    constexpr reverse_iterator rend() const noexcept;
    constexpr const_reverse_iterator crbegin() const noexcept;
    constexpr const_reverse_iterator crend() const noexcept;

    constexpr pointer data() const noexcept;
    constexpr bool empty() const noexcept;
    constexpr size_type size() const noexcept;
    constexpr size_type size_bytes() const noexcept;
    constexpr reference operator[](size_type index) const noexcept;
    constexpr reference front() const noexcept;
    constexpr reference back() const noexcept;

    constexpr span first(size_type how_many) const noexcept;
    constexpr span drop_first(size_type how_many) const noexcept;
private:
    T* data_begin = nullptr;
    T* data_end = nullptr;
};

template <typename T>
span<const std::byte> as_bytes(span<T> s) noexcept
{
    return span(reinterpret_cast<const std::byte*>(s.data()), s.size_bytes());
}

template <typename T>
constexpr span<T>::span(T* begin, T* end) noexcept
    : data_begin(begin), data_end(end)
{
}

template <typename T>
constexpr span<T>::span(T* begin, std::size_t size) noexcept
    : data_begin(begin), data_end(begin + size)
{
}

template <typename T>
template <typename U, typename>
constexpr span<T>::span(U& container)
    : data_begin(std::data(container)), data_end(data_begin + std::size(container))
{
}

template <typename T>
template <typename U, typename>
constexpr span<T>::span(span<U> other) noexcept
    : data_begin(other.data()), data_end(data_begin + other.size())
{
}

template <typename T>
constexpr auto span<T>::begin() const noexcept -> iterator
{
    return data_begin;
}

template <typename T>
constexpr auto span<T>::end() const noexcept -> iterator
{
    return data_end;
}

template <typename T>
constexpr auto span<T>::cbegin() const noexcept -> const_iterator
{
    return data_begin;
}

template <typename T>
constexpr auto span<T>::cend() const noexcept -> const_iterator
{
    return data_end;
}

template <typename T>
constexpr auto span<T>::rbegin() const noexcept -> reverse_iterator
{
    return reverse_iterator(data_end);
}

template <typename T>
constexpr auto span<T>::rend() const noexcept -> reverse_iterator
{
    return reverse_iterator(data_begin);
}

template <typename T>
constexpr auto span<T>::crbegin() const noexcept -> const_reverse_iterator
{
    return const_reverse_iterator(data_end);
}

template <typename T>
constexpr auto span<T>::crend() const noexcept -> const_reverse_iterator
{
    return const_reverse_iterator(data_begin);
}

template <typename T>
constexpr auto span<T>::data() const noexcept -> pointer
{
    return data_begin;
}

template <typename T>
constexpr bool span<T>::empty() const noexcept
{
    return data_begin == data_end;
}

template <typename T>
constexpr auto span<T>::size() const noexcept -> size_type
{
    return static_cast<size_type>(data_end - data_begin);
}

template <typename T>
constexpr auto span<T>::size_bytes() const noexcept -> size_type
{
    return size() * sizeof(T);
}

template <typename T>
constexpr auto span<T>::operator[](size_type index) const noexcept -> reference
{
    assert(index < size() && "span index out of bounds");
    return data_begin[index];
}

template <typename T>
constexpr auto span<T>::front() const noexcept -> reference
{
    assert(data_begin != data_end && "front called on an empty span");
    return *data_begin;
}

template <typename T>
constexpr auto span<T>::back() const noexcept -> reference
{
    assert(data_begin != data_end && "back called on an empty span");
    return data_end[-1];
}

template <typename T>
constexpr span<T> span<T>::first(size_type how_many) const noexcept
{
    const auto elements_to_use = std::min(how_many, size());
    return span(data_begin, data_begin + elements_to_use);
}

template <typename T>
constexpr span<T> span<T>::drop_first(size_type how_many) const noexcept
{
    const auto elements_to_drop = std::min(how_many, size());
    return span(data_begin + elements_to_drop, data_end);
}

} // namespace filehash
#endif
