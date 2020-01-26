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
#include "file-descriptor.hh"
#include "file-watcher.hh"

namespace filehash {

const char* watch_error::what() const noexcept
{
    return "watch error";
}


// Define it here so that the vtable is emitted once instead of in every file
// that includes the header.
file_watcher::~file_watcher() noexcept = default;


file_watcher::watch::watch(file_watcher& parent, int descriptor, access_token) noexcept
    : parent(&parent, {descriptor})
{
}

int file_watcher::watch::descriptor() const noexcept
{
    return parent.get_deleter().descriptor;
}

void file_watcher::watch::deleter::operator()(file_watcher* parent) const noexcept
{
    parent->delete_watch(descriptor);
}


file_watcher::event::event(file_watcher& parent, const void* data, access_token) noexcept
    : parent(&parent), opaque_data(data)
{
}

int file_watcher::event::descriptor() const noexcept
{
    return parent->event_descriptor(opaque_data);
}

bool file_watcher::event::is_write_event() const noexcept
{
    return parent->event_is_write(opaque_data);
}

} // namespace filehash
