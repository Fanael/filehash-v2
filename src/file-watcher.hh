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
#ifndef INCLUDED_AB77DD0C55DC45AE9885D96DD4ABF08F
#define INCLUDED_AB77DD0C55DC45AE9885D96DD4ABF08F
#include <memory>
#include "syscall-error.hh"

namespace filehash {

class file_watcher_error : public syscall_error {
public:
    using syscall_error::syscall_error;
    const char* what() const noexcept override;
};

class file_watcher {
public:
    class watch;
    class event;

    file_watcher();

    watch add_write_watch_for(const char* path, int fd);
    bool events_available() const;
    event next_event();
private:
    class implementation;

    struct deleter {
        void operator()(implementation* impl) const noexcept;
    };
    std::unique_ptr<implementation, deleter> impl;
};

class file_watcher::watch {
public:
    int descriptor() const noexcept;
private:
    friend class implementation;
    // NB: only a pointer so that the dummy watcher doesn't have to create
    // an instance, it's meant to be always non-null otherwise.
    watch(implementation* parent, int descriptor) noexcept;

    struct deleter {
        void operator()(implementation* parent) const noexcept;

        int descriptor;
    };
    std::unique_ptr<implementation, deleter> parent;
};

class file_watcher::event {
public:
    int descriptor() const noexcept;
    bool is_write_event() const noexcept;
private:
    friend class implementation;
    explicit event(const void* data) noexcept;

    const void* opaque_data;
};

} // namespace filehash
#endif
