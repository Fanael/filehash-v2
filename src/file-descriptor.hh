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
#ifndef INCLUDED_22B04CB697ED4FA7971F1935FF42E771
#define INCLUDED_22B04CB697ED4FA7971F1935FF42E771
#include <cstddef>
#include <optional>
#include <sys/types.h>
#include "syscall-error.hh"

struct stat;

namespace filehash {

template <typename T>
class span;

class file_error : public syscall_error {
public:
    using syscall_error::syscall_error;
    const char* what() const noexcept override;
};

class file_descriptor {
public:
    explicit file_descriptor(int fd) noexcept;
    ~file_descriptor() noexcept;
    file_descriptor(file_descriptor&& other) noexcept;
    file_descriptor& operator=(file_descriptor other) noexcept;
    file_descriptor(const file_descriptor&) = delete;

    int fd() const noexcept;
    struct ::stat stat() const;
    void rewind() const;
    [[nodiscard]] span<std::byte> read(span<std::byte> buffer) const;
    [[nodiscard]] std::optional<span<std::byte>> read_nonblocking(span<std::byte> buffer) const;
    void drop_o_nonblock() const;
    void fadvise(int mode, off_t offset = 0, off_t len = 0) const;
private:
    int descriptor;
};

} // namespace filehash
#endif
