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
#include "sha384.hh"
#include "span.hh"

namespace filehash {

sha384::sha384() noexcept
{
    reset();
}

void sha384::reset() noexcept
{
    SHA384_Init(&sha_context);
}

void sha384::update(span<const std::byte> bytes) noexcept
{
    SHA384_Update(&sha_context, bytes.data(), bytes.size_bytes());
}

auto sha384::finalize() noexcept -> result_type
{
    result_type result;
    SHA384_Final(reinterpret_cast<unsigned char*>(result.data()), &sha_context);
    return result;
}

} // namespace filehash
