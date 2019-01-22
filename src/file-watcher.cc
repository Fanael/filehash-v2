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
#include "config.hh"
#include "file-watcher.hh"
#if defined(FILEHASH_USE_INOTIFY_WATCHER)
# include <algorithm>
# include <array>
# include <cstddef>
# include <limits.h>
# include <sys/inotify.h>
# include "file-descriptor.hh"
# include "span.hh"
# include "syscall-utils.hh"
#elif defined(FILEHASH_USE_KQUEUE_WATCHER)
# include <array>
# include <sys/event.h>
# include <time.h>
# include "file-descriptor.hh"
# include "span.hh"
# include "syscall-utils.hh"
#endif

namespace filehash {

const char* file_watcher_error::what() const noexcept
{
    return "watch error";
}


#if !defined(FILEHASH_USE_DUMMY_WATCHER)
# if defined(FILEHASH_USE_INOTIFY_WATCHER)
namespace {

template <typename From, typename Func>
decltype(auto) translate_exception(Func function)
{
    try {
        return function();
    } catch(const From& e) {
        throw file_watcher_error(e.code());
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

    watch add_write_watch_for(const char* path, int fd);
    std::optional<event> next_event();
    void remove_watch(int descriptor) noexcept;
private:
    static constexpr std::size_t buffer_size = std::max(std::size_t{1024},
        sizeof(inotify_event) + NAME_MAX + 1);

    span<const std::byte> remaining_event_bytes;
    file_descriptor inotify_fd;
    alignas(alignof(inotify_event)) std::array<std::byte, buffer_size> event_buffer;
};


file_watcher::implementation::implementation()
    : inotify_fd(throw_errno_if_failed<file_watcher_error>(inotify_init1(IN_NONBLOCK | IN_CLOEXEC)))
{
}

auto file_watcher::implementation::add_write_watch_for(const char* path, int) -> watch
{
    const int wd = throw_errno_if_failed<file_watcher_error>(
        inotify_add_watch(inotify_fd.fd(), path, IN_MODIFY));
    return watch(this, wd);
}

auto file_watcher::implementation::next_event() -> std::optional<event>
{
    if(remaining_event_bytes.empty()) {
        // No events left in the buffer, need to read more events from the fd.
        const auto read_data = translate_exception<file_error>(
            [&] { return inotify_fd.read_nonblocking(event_buffer); });
        if(!read_data) {
            return std::nullopt;
        }
        remaining_event_bytes = *read_data;
    }
    const auto ev = reinterpret_cast<const inotify_event*>(remaining_event_bytes.data());
    remaining_event_bytes = remaining_event_bytes.drop_first(sizeof(inotify_event) + ev->len);
    return event(ev);
}

void file_watcher::implementation::remove_watch(int descriptor) noexcept
{
    inotify_rm_watch(inotify_fd.fd(), descriptor);
}


int file_watcher::event::descriptor() const noexcept
{
    return static_cast<const inotify_event*>(opaque_data)->wd;
}

bool file_watcher::event::is_write_event() const noexcept
{
    return (static_cast<const inotify_event*>(opaque_data)->mask & IN_MODIFY) != 0;
}

file_watcher::event::event(const void* data) noexcept
    : opaque_data(data)
{
}
# elif defined(FILEHASH_USE_KQUEUE_WATCHER)
class file_watcher::implementation {
public:
    implementation();
    // We don't want to move objects of this class ever, because watches
    // we create contain parent pointers to their creators.
    implementation(implementation&&) = delete;
    implementation& operator=(implementation&&) = delete;

    watch add_write_watch_for(const char* path, int fd);
    std::optional<event> next_event();
    void remove_watch(int descriptor) noexcept;
private:
    file_descriptor kqueue_fd;
    std::array<struct kevent, 20> event_buffer;
    span<const struct kevent> remaining_events;
};

file_watcher::implementation::implementation()
    : kqueue_fd(throw_errno_if_failed<file_watcher_error>(kqueue()))
{
}

auto file_watcher::implementation::add_write_watch_for(const char*, int fd) -> watch
{
    struct kevent new_event;
    EV_SET(&new_event, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0, nullptr);
    throw_errno_if_failed<file_watcher_error>(
        kevent(kqueue_fd.fd(), &new_event, 1, nullptr, 0, nullptr));
    return watch(this, fd);
}

auto file_watcher::implementation::next_event() -> std::optional<event>
{
    if(remaining_events.empty()) {
        const timespec zero_timeout = {};
        const auto events_received =
            static_cast<unsigned>(throw_errno_if_failed<file_watcher_error>(
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

void file_watcher::implementation::remove_watch(int descriptor) noexcept
{
    struct kevent event_to_delete;
    EV_SET(&event_to_delete, descriptor, EVFILT_VNODE, EV_DELETE, NOTE_WRITE, 0, nullptr);
    kevent(kqueue_fd.fd(), &event_to_delete, 1, nullptr, 0, nullptr);
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

file_watcher::event::event(const void* data) noexcept
    : opaque_data(data)
{
}
# endif


file_watcher::file_watcher()
    // Cannot use make_unique here because this unique_ptr has a custom
    // deleter.
    : impl(new implementation)
{
}

auto file_watcher::add_write_watch_for(const char* path, int fd) -> watch
{
    return impl->add_write_watch_for(path, fd);
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
    parent->remove_watch(descriptor);
}
#else
class file_watcher::implementation {
public:
    static watch make_dummy_watch() noexcept;
};

auto file_watcher::implementation::make_dummy_watch() noexcept -> watch
{
    return watch(nullptr, 0);
}


file_watcher::file_watcher()
{
}

auto file_watcher::add_write_watch_for(const char*, int) -> watch
{
    return implementation::make_dummy_watch();
}

auto file_watcher::next_event() -> std::optional<event>
{
    return std::nullopt;
}

void file_watcher::deleter::operator()(implementation*) const noexcept
{
}


int file_watcher::watch::descriptor() const noexcept
{
    return -1;
}

file_watcher::watch::watch(implementation*, int) noexcept
    : parent(nullptr, {0})
{
}

void file_watcher::watch::deleter::operator()(implementation*) const noexcept
{
}


int file_watcher::event::descriptor() const noexcept
{
    return -1;
}

bool file_watcher::event::is_write_event() const noexcept
{
    return false;
}

file_watcher::event::event(const void*) noexcept
    : opaque_data(nullptr)
{
}
#endif

} // namespace filehash
