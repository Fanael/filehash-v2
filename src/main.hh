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
#ifndef INCLUDED_07FD00920FE049758AC2DC9082033BA3
#define INCLUDED_07FD00920FE049758AC2DC9082033BA3
namespace filehash {

#define FILEHASH_FOR_EACH_EXIT_CODE(macro)\
    macro(success, 0, "Operation completed successfully")\
    macro(harmless_error, 1, "Operation failed, but the error was harmless")\
    macro(mismatch_found, 2, "Mismatches found between files")\
    macro(error, 3, "An error occurred")\
    macro(usage, 64, "Command line argument parsing failed")

enum class exit_status : int {
#define FILEHASH_DEFINE_EXIT_STATUS_ENUM(name, value, _description) name = (value),
    FILEHASH_FOR_EACH_EXIT_CODE(FILEHASH_DEFINE_EXIT_STATUS_ENUM)
#undef FILEHASH_DEFINE_EXIT_STATUS_ENUM
};

} // namespace filehash
#endif
