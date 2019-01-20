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
#ifndef INCLUDED_AB77DD0C55DC45AE9885D96DD4ABF08F
#define INCLUDED_AB77DD0C55DC45AE9885D96DD4ABF08F
#include <cstdint>
#include <memory>
#include <type_traits>
#include <limits.h>
#include <sys/inotify.h>
#include "file-descriptor.hh"

namespace filehash {

class inotify_error : public syscall_error {
public:
    using syscall_error::syscall_error;
    const char* what() const noexcept override;
};

class inotify {
public:
    class watch;

    inotify();
    // We can't easily move this class because it has internal pointers
    // to the event buffer, and watches keep a pointer to their parent
    // inotify, so disable move operations.
    inotify(inotify&&) = delete;
    inotify& operator=(inotify&&) = delete;

    watch add_watch(const char* path, std::uint32_t mask);
    bool events_available() const;
    const inotify_event& next_event();
private:
    static constexpr size_t buffer_size = sizeof(inotify_event) + NAME_MAX + 1;

    file_descriptor fd;
    char* next_event_ptr = nullptr;
    char* events_end = nullptr;
    std::aligned_storage_t<buffer_size, alignof(inotify_event)> event_buffer;
};

class inotify::watch {
public:
    int descriptor() const noexcept;
private:
    friend class inotify;
    watch(inotify& parent, int descriptor) noexcept;

    struct deleter {
        void operator()(inotify* parent) const noexcept;

        int descriptor;
    };
    std::unique_ptr<inotify, deleter> parent;
};

} // namespace filehash
#endif
