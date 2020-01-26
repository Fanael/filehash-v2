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
#ifndef INCLUDED_D9B40AE0D3B740FEA3F9E53B8D442F9C
#define INCLUDED_D9B40AE0D3B740FEA3F9E53B8D442F9C
#include <exception>

namespace filehash {

class syscall_error : public std::exception {
public:
    explicit syscall_error(int code) noexcept;
    const char* what() const noexcept override;
    int code() const noexcept;
private:
    int error_code;
};

} // namespace filehash
#endif
