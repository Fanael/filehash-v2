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
#include "compiler.hh"
#if defined(FILEHASH_UNREACHABLE_USE_FALLBACK)
#include <exception>
#include <iostream>

namespace filehash {

void unreachable_fallback()
{
    std::cerr << "Control reached an unreachable point, this should never happen!\n";
    std::terminate();
}

} // namespace filehash
#endif
