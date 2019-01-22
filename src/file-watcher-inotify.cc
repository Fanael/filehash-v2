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
#include <algorithm>
#include <array>
#include <cstddef>
#include <limits.h>
#include <sys/inotify.h>
#include "file-descriptor.hh"
#include "file-watcher.hh"
#include "span.hh"
#include "syscall-utils.hh"

namespace filehash {
namespace {

template <typename From, typename Func>
decltype(auto) translate_exception(Func function)
{
    try {
        return function();
    } catch(const From& e) {
        throw watch_error(e.code());
    }
}

} // unnamed namespace

class file_watcher::implementation {
public:
    implementation();
    // We don't want to move objects of this class ever, because watches
    // we create contain parent pointers to their creators.
    implementation(implementation&&) = delete;
    implementation& operator=(implementation&&) = delete;

    watch add_write_watch_for(const char* path);
    std::optional<event> next_event();
private:
    friend class watch;
    static constexpr std::size_t buffer_size = std::max(std::size_t{1024},
        sizeof(inotify_event) + NAME_MAX + 1);

    span<const std::byte> remaining_event_bytes;
    file_descriptor inotify_fd;
    alignas(alignof(inotify_event)) std::array<std::byte, buffer_size> event_buffer;
};


file_watcher::implementation::implementation()
    : inotify_fd(throw_errno_if_failed<watch_error>(inotify_init1(IN_NONBLOCK | IN_CLOEXEC)))
{
}

auto file_watcher::implementation::add_write_watch_for(const char* path) -> watch
{
    const int wd = throw_errno_if_failed<watch_error>(
        inotify_add_watch(inotify_fd.fd(), path, IN_MODIFY));
    return watch(this, wd);
}

auto file_watcher::implementation::next_event() -> std::optional<event>
{
    if(remaining_event_bytes.empty()) {
        // No events left in the buffer, need to read more events from the fd.
        const auto read_data = translate_exception<file_error>(
            [&]{ return inotify_fd.read_nonblocking(event_buffer); });
        if(!read_data) {
            return std::nullopt;
        }
        remaining_event_bytes = *read_data;
    }
    const auto ev = reinterpret_cast<const inotify_event*>(remaining_event_bytes.data());
    remaining_event_bytes = remaining_event_bytes.drop_first(sizeof(inotify_event) + ev->len);
    return event(ev);
}


file_watcher::file_watcher()
    // Cannot use make_unique here because this unique_ptr has a custom
    // deleter.
    : impl(new implementation)
{
}

auto file_watcher::add_write_watch_for(const char* path, int) -> watch
{
    return impl->add_write_watch_for(path);
}

auto file_watcher::next_event() -> std::optional<event>
{
    return impl->next_event();
}

void file_watcher::deleter::operator()(implementation* impl) const noexcept
{
    delete impl;
}


int file_watcher::watch::descriptor() const noexcept
{
    return parent.get_deleter().descriptor;
}

file_watcher::watch::watch(implementation* parent, int descriptor) noexcept
    : parent(parent, {descriptor})
{
}

void file_watcher::watch::deleter::operator()(implementation* parent) const noexcept
{
    inotify_rm_watch(parent->inotify_fd.fd(), descriptor);
}


int file_watcher::event::descriptor() const noexcept
{
    return static_cast<const inotify_event*>(opaque_data)->wd;
}

bool file_watcher::event::is_write_event() const noexcept
{
    return (static_cast<const inotify_event*>(opaque_data)->mask & IN_MODIFY) != 0;
}

} // namespace filehash
