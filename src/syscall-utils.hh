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
#ifndef INCLUDED_CF3C4DCEF42C4DFA973453D974077F6A
#define INCLUDED_CF3C4DCEF42C4DFA973453D974077F6A
#include <utility>
#include <errno.h>

namespace filehash {

template <typename Exception>
[[noreturn]] void throw_syscall_error(int code)
{
    throw Exception(code);
}

template <typename Exception>
[[noreturn]] void throw_errno()
{
    throw_syscall_error<Exception>(errno);
}

template <typename Exception, typename T>
T throw_errno_if_failed(T result)
{
    if(result == -1) {
        throw_errno<Exception>();
    }
    return result;
}

template <typename Func>
decltype(auto) retry_on_eintr(Func&& function)
{
    for(;;) {
        auto result = function();
        if(result == -1 && errno == EINTR) {
            continue;
        }
        return result;
    }
}

template <typename Exception, typename Func>
decltype(auto) wrap_syscall(Func&& function)
{
    return throw_errno_if_failed<Exception>(retry_on_eintr(std::forward<Func>(function)));
}

template <typename Exception, typename Func>
auto wrap_syscall_nonblocking(Func&& function)
{
    auto result = retry_on_eintr(std::forward<Func>(function));
    if(result != -1) {
        return std::optional(std::move(result));
    }
    const auto error = errno;
    if(error == EAGAIN || error == EWOULDBLOCK) {
        return std::optional<decltype(result)>(std::nullopt);
    }
    throw_syscall_error<Exception>(error);
}

} // namespace filehash
#endif
