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
#include <optional>
#include "syscall-error.hh"

namespace filehash {

class watch_error : public syscall_error {
public:
    using syscall_error::syscall_error;
    const char* what() const noexcept override;
};

class file_watcher {
public:
    class watch;
    class event;

    // Most implementations can't be moved because of internal pointers,
    // and this class is meant to be used only through a pointer or
    // a reference anyway, so disable copies and moves here.
    file_watcher(const file_watcher&) = delete;
    file_watcher(file_watcher&&) = delete;
    file_watcher& operator=(const file_watcher&) = delete;
    file_watcher& operator=(file_watcher&&) = delete;
    virtual ~file_watcher() noexcept;

    virtual watch add_write_watch_for(const char* path, int fd) = 0;
    virtual std::optional<event> next_event() = 0;
protected:
    struct access_token {};

    file_watcher() noexcept = default;
private:
    virtual void delete_watch(int descriptor) noexcept = 0;
    virtual int event_descriptor(const void* event_pointer) const noexcept = 0;
    virtual bool event_is_write(const void* event_pointer) const noexcept = 0;
};

class file_watcher::watch {
public:
    watch(file_watcher& parent, int descriptor, access_token) noexcept;

    int descriptor() const noexcept;
private:
    struct deleter {
        void operator()(file_watcher* parent) const noexcept;

        int descriptor;
    };
    std::unique_ptr<file_watcher, deleter> parent;
};

class file_watcher::event {
public:
    explicit event(file_watcher& parent, const void* data, access_token) noexcept;

    int descriptor() const noexcept;
    bool is_write_event() const noexcept;
private:
    file_watcher* parent;
    const void* opaque_data;
};

std::unique_ptr<file_watcher> make_system_watcher();
std::unique_ptr<file_watcher> make_dummy_watcher();

} // namespace filehash
#endif
