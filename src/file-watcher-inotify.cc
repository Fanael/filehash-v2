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
#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
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

class file_watcher_inotify final : public file_watcher {
public:
    file_watcher_inotify();

    watch add_write_watch_for(const char* path, int) override;
    std::optional<event> next_event() override;
private:
    void delete_watch(int descriptor) noexcept override;
    int event_descriptor(const void* event_pointer) const noexcept override;
    bool event_is_write(const void* event_pointer) const noexcept override;

    static constexpr std::size_t buffer_size = std::max(std::size_t{1024},
        sizeof(inotify_event) + NAME_MAX + 1);

    span<const std::byte> remaining_event_bytes;
    file_descriptor inotify_fd;
    alignas(alignof(inotify_event)) std::array<std::byte, buffer_size> event_buffer;
};


file_watcher_inotify::file_watcher_inotify()
    : inotify_fd(throw_errno_if_failed<watch_error>(inotify_init1(IN_NONBLOCK | IN_CLOEXEC)))
{
}

auto file_watcher_inotify::add_write_watch_for(const char* path, int) -> watch
{
    const int wd = throw_errno_if_failed<watch_error>(
        inotify_add_watch(inotify_fd.fd(), path, IN_MODIFY));
    return watch(*this, wd, access_token{});
}

auto file_watcher_inotify::next_event() -> std::optional<event>
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
    return event(*this, ev, access_token{});
}

void file_watcher_inotify::delete_watch(int descriptor) noexcept
{
    inotify_rm_watch(inotify_fd.fd(), descriptor);
}

int file_watcher_inotify::event_descriptor(const void* event_pointer) const noexcept
{
    return static_cast<const inotify_event*>(event_pointer)->wd;
}

bool file_watcher_inotify::event_is_write(const void* event_pointer) const noexcept
{
    return (static_cast<const inotify_event*>(event_pointer)->mask & IN_MODIFY) != 0;
}

} // unnamed namespace

std::unique_ptr<file_watcher> make_system_watcher()
{
    return std::make_unique<file_watcher_inotify>();
}

} // namespace filehash
