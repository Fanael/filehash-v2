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
#include "inotify.hh"
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
        throw inotify_error(e.code());
    }
}

} // unnamed namespace

const char* inotify_error::what() const noexcept
{
    return "inotify error";
}


inotify::inotify()
    : fd(throw_errno_if_failed<inotify_error>(inotify_init1(IN_CLOEXEC)))
{
}

auto inotify::add_watch(const char* path, uint32_t mask) -> watch
{
    const int wd = throw_errno_if_failed<inotify_error>(inotify_add_watch(fd.fd(), path, mask));
    return watch(*this, wd);
}

bool inotify::events_available() const
{
    return next_event_ptr < events_end || translate_exception<file_error>(
        [&] {return fd.input_available();});
}

const inotify_event& inotify::next_event()
{
    if(next_event_ptr >= events_end) {
        // No events left in the buffer, need to read more events from the fd.
        const auto read_data = translate_exception<file_error>(
            [&] {return fd.read({reinterpret_cast<std::byte*>(&event_buffer), buffer_size});});
        next_event_ptr = reinterpret_cast<char*>(read_data.data());
        events_end = next_event_ptr + read_data.size_bytes();
    }
    const auto event = reinterpret_cast<const inotify_event*>(next_event_ptr);
    next_event_ptr += sizeof(inotify_event) + event->len;
    return *event;
}

int inotify::watch::descriptor() const noexcept
{
    return parent.get_deleter().descriptor;
}

inotify::watch::watch(inotify& parent, int descriptor) noexcept
    : parent(&parent, {descriptor})
{
}

void inotify::watch::deleter::operator()(inotify* parent) const noexcept
{
    inotify_rm_watch(parent->fd.fd(), descriptor);
}

} // namespace filehash
