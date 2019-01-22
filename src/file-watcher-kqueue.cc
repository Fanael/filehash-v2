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
#include <array>
#include <sys/event.h>
#include <time.h>
#include "file-descriptor.hh"
#include "file-watcher.hh"
#include "span.hh"
#include "syscall-utils.hh"

namespace filehash {

class file_watcher::implementation {
public:
    implementation();
    // We don't want to move objects of this class ever, because watches
    // we create contain parent pointers to their creators.
    implementation(implementation&&) = delete;
    implementation& operator=(implementation&&) = delete;

    watch add_write_watch_for(int fd);
    std::optional<event> next_event();
private:
    friend class watch;
    file_descriptor kqueue_fd;
    std::array<struct kevent, 20> event_buffer;
    span<const struct kevent> remaining_events;
};

file_watcher::implementation::implementation()
    : kqueue_fd(throw_errno_if_failed<watch_error>(kqueue()))
{
}

auto file_watcher::implementation::add_write_watch_for(int fd) -> watch
{
    struct kevent new_event;
    EV_SET(&new_event, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0, nullptr);
    throw_errno_if_failed<watch_error>(
        kevent(kqueue_fd.fd(), &new_event, 1, nullptr, 0, nullptr));
    return watch(this, fd);
}

auto file_watcher::implementation::next_event() -> std::optional<event>
{
    if(remaining_events.empty()) {
        const timespec zero_timeout = {};
        const auto events_received =
            static_cast<unsigned>(throw_errno_if_failed<watch_error>(
                kevent(kqueue_fd.fd(), nullptr, 0, event_buffer.data(),
                    static_cast<int>(event_buffer.size()), &zero_timeout)));
        remaining_events = span(event_buffer.data(), events_received);
        if(events_received == 0) {
            return std::nullopt;
        }
    }
    const auto event_ptr = &remaining_events.front();
    remaining_events = remaining_events.drop_first(1);
    return event(event_ptr);
}


file_watcher::file_watcher()
    // Cannot use make_unique here because this unique_ptr has a custom
    // deleter.
    : impl(new implementation)
{
}

auto file_watcher::add_write_watch_for(const char*, int fd) -> watch
{
    return impl->add_write_watch_for(fd);
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
    struct kevent event_to_delete;
    EV_SET(&event_to_delete, descriptor, EVFILT_VNODE, EV_DELETE, NOTE_WRITE, 0, nullptr);
    kevent(parent->kqueue_fd.fd(), &event_to_delete, 1, nullptr, 0, nullptr);
}


int file_watcher::event::descriptor() const noexcept
{
    return static_cast<int>(static_cast<const struct kevent*>(opaque_data)->ident);
}

bool file_watcher::event::is_write_event() const noexcept
{
    const auto event_ptr = static_cast<const struct kevent*>(opaque_data);
    return event_ptr->filter == EVFILT_VNODE && (event_ptr->fflags & NOTE_WRITE) != 0;
}

} // namespace filehash
