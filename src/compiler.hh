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
#ifndef INCLUDED_F0FD2EC1F155482899966D5C55887565
#define INCLUDED_F0FD2EC1F155482899966D5C55887565

#if defined(__has_builtin)
# define FILEHASH_HAS_BUILTIN __has_builtin
#else
# define FILEHASH_HAS_BUILTIN(...) 0
#endif

#if FILEHASH_HAS_BUILTIN(__builtin_unreachable) || defined(__GNUC__)
# define FILEHASH_UNREACHABLE() __builtin_unreachable()
#else
# define FILEHASH_UNREACHABLE_USE_FALLBACK
# define FILEHASH_UNREACHABLE() ::filehash::unreachable_fallback()
#endif

#if defined(FILEHASH_UNREACHABLE_USE_FALLBACK)
namespace filehash {
[[noreturn]] void unreachable_fallback();
} // namespace filehash
#endif

#endif
