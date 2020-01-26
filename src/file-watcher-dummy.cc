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
#include <memory>
#include "config.hh"
#include "file-watcher.hh"

namespace filehash {
namespace {

class file_watcher_dummy final : public file_watcher {
public:
    file_watcher_dummy() noexcept = default;

    watch add_write_watch_for(const char*, int) noexcept override;
    std::optional<event> next_event() noexcept override;
private:
    void delete_watch(int) noexcept override;
    int event_descriptor(const void*) const noexcept override;
    bool event_is_write(const void*) const noexcept override;
};

auto file_watcher_dummy::add_write_watch_for(const char*, int) noexcept -> watch
{
    return watch(*this, -1, access_token());
}

auto file_watcher_dummy::next_event() noexcept -> std::optional<event>
{
    return std::nullopt;
}

void file_watcher_dummy::delete_watch(int) noexcept
{
}

int file_watcher_dummy::event_descriptor(const void*) const noexcept
{
    return -1;
}

bool file_watcher_dummy::event_is_write(const void*) const noexcept
{
    return false;
}

} // unnamed namespace

#ifdef FILEHASH_DUMMY_WATCHER_ONLY
std::unique_ptr<file_watcher> make_system_watcher()
{
    return std::make_unique<file_watcher_dummy>();
}
#endif

std::unique_ptr<file_watcher> make_dummy_watcher()
{
    return std::make_unique<file_watcher_dummy>();
}

} // namespace filehash
