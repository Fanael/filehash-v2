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
#include "file-watcher.hh"

namespace filehash {

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

} // namespace filehash
