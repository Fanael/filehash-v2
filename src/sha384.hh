// Copyright 2019 Fanael Linithien
//
// This file is part of filehash-v2.
//
// filehash-v2 is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// In addition, for the avoidance of any doubt, permission is granted to
// link filehash-v2 with OpenSSL or any other library package and to
// (re)distribute the binaries produced as the result of such linking.
//
// filehash-v2 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with filehash-v2.  If not, see <https://www.gnu.org/licenses/>.
#ifndef INCLUDED_07D44930879A48619D8EF581D4AB1B14
#define INCLUDED_07D44930879A48619D8EF581D4AB1B14
#include <array>
#include <cstddef>
#include <openssl/sha.h>

namespace filehash {

template <typename T>
class span;

class sha384 {
public:
    using result_type = std::array<std::byte, 48>;

    sha384() noexcept;
    void reset() noexcept;
    void update(span<const std::byte> bytes) noexcept;
    result_type finalize() noexcept;
private:
    SHA512_CTX sha_context;
};

} // namespace filehash
#endif
