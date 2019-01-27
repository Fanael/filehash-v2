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
#include <memory>
#include <optional>
#include <sys/event.h>
#include <time.h>
#include "file-descriptor.hh"
#include "file-watcher.hh"
#include "span.hh"
#include "syscall-utils.hh"

namespace filehash {
namespace {

class file_watcher_kqueue final : public file_watcher {
public:
    file_watcher_kqueue();

    watch add_write_watch_for(const char*, int fd) override;
    std::optional<event> next_event() override;
private:
    void delete_watch(int descriptor) noexcept override;
    int event_descriptor(const void* event_pointer) const noexcept override;
    bool event_is_write(const void* event_pointer) const noexcept override;

    file_descriptor kqueue_fd;
    std::array<struct kevent, 20> event_buffer;
    span<const struct kevent> remaining_events;
};

file_watcher_kqueue::file_watcher_kqueue()
    : kqueue_fd(throw_errno_if_failed<watch_error>(kqueue()))
{
}

auto file_watcher_kqueue::add_write_watch_for(const char*, int fd) -> watch
{
    struct kevent new_event;
    EV_SET(&new_event, fd.fd(), EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0, nullptr);
    throw_errno_if_failed<watch_error>(
        kevent(kqueue_fd.fd(), &new_event, 1, nullptr, 0, nullptr));
    return watch(*this, fd, access_token{});
}

auto file_watcher_kqueue::next_event() -> std::optional<event>
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
    return event(*this, event_ptr, access_token{});
}

void file_watcher_kqueue::delete_watch(int descriptor) noexcept
{
    struct kevent event_to_delete;
    EV_SET(&event_to_delete, descriptor, EVFILT_VNODE, EV_DELETE, NOTE_WRITE, 0, nullptr);
    kevent(kqueue_fd.fd(), &event_to_delete, 1, nullptr, 0, nullptr);
}


int file_watcher_kqueue::event_descriptor(const void* event_pointer) const noexcept
{
    return static_cast<int>(static_cast<const struct kevent*>(event_pointer)->ident);
}

bool file_watcher_kqueue::event_is_write(const void* event_pointer) const noexcept
{
    const auto event_ptr = static_cast<const struct kevent*>(event_pointer);
    return event_ptr->filter == EVFILT_VNODE && (event_ptr->fflags & NOTE_WRITE) != 0;
}

} // unnamed namespace

std::unique_ptr<file_watcher> make_system_watcher()
{
    return std::make_unique<file_watcher_kqueue>();
}

} // namespace filehash
