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
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
#include "file-descriptor.hh"
#include "span.hh"
#include "syscall-utils.hh"

namespace filehash {

const char* file_error::what() const noexcept
{
    return "file error";
}

file_descriptor::file_descriptor(int fd) noexcept
    : descriptor(fd)
{
}

file_descriptor::~file_descriptor() noexcept
{
    close(descriptor);
}

file_descriptor::file_descriptor(file_descriptor&& other) noexcept
    : descriptor(other.descriptor)
{
    // Any always-invalid descriptor that will harmlessly fail on close
    // will do.
    other.descriptor = -1;
}

file_descriptor& file_descriptor::operator=(file_descriptor other) noexcept
{
    std::swap(descriptor, other.descriptor);
    return *this;
}

int file_descriptor::fd() const noexcept
{
    return descriptor;
}

struct ::stat file_descriptor::stat() const
{
    struct ::stat result;
    throw_errno_if_failed<file_error>(fstat(descriptor, &result));
    return result;
}

void file_descriptor::rewind() const
{
    throw_errno_if_failed<file_error>(lseek(descriptor, 0, SEEK_SET));
}

span<std::byte> file_descriptor::read(span<std::byte> buffer) const
{
    const auto read_bytes = static_cast<std::size_t>(wrap_syscall<file_error>(
        [&]{ return ::read(descriptor, buffer.data(), buffer.size_bytes()); }));
    return buffer.first(read_bytes);
}

std::optional<span<std::byte>> file_descriptor::read_nonblocking(span<std::byte> buffer) const
{
    const auto read_bytes = wrap_syscall_nonblocking<file_error>(
        [&]{ return ::read(descriptor, buffer.data(), buffer.size_bytes()); });
    return read_bytes
        ? std::optional(buffer.first(static_cast<std::size_t>(*read_bytes)))
        : std::nullopt;
}

void file_descriptor::drop_o_nonblock() const
{
    const int old_flags = throw_errno_if_failed<file_error>(fcntl(descriptor, F_GETFL));
    const int new_flags = old_flags & ~O_NONBLOCK;
    throw_errno_if_failed<file_error>(fcntl(descriptor, F_SETFL, new_flags));
}

void file_descriptor::fadvise(int mode, off_t offset, off_t len) const
{
    // Don't check for errors because it's only a hint.
    posix_fadvise(descriptor, offset, len, mode);
}

} // namespace filehash
