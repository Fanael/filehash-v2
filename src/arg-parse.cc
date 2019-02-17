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
#include <cstdint>
#include <ostream>
#include <string_view>
#include <utility>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/lexical_cast.hpp>
#include "arg-parse.hh"
#include "main.hh"
#include "span.hh"

namespace filehash::args {

namespace {

using command_parser = command (*)(command_cookie, span<const std::string_view>);

struct command_spec {
    std::string_view name;
    command_parser parser;
    std::string_view readable_arg_spec;
    std::string_view short_description;
    std::string_view long_description;
};

constexpr const command_spec& cookie_to_command(command_cookie cookie) noexcept;
constexpr command_cookie command_to_cookie(const command_spec& command) noexcept;


class commandless_parse_error : public parse_error {
private:
    command_cookie command() const noexcept override;
};

command_cookie commandless_parse_error::command() const noexcept
{
    return command_cookie();
}

class commandful_parse_error : public parse_error {
public:
    explicit commandful_parse_error(command_cookie cookie) noexcept;
private:
    command_cookie command() const noexcept override;

    command_cookie cookie;
};

commandful_parse_error::commandful_parse_error(command_cookie cookie) noexcept
    : cookie(cookie)
{
}

command_cookie commandful_parse_error::command() const noexcept
{
    return cookie;
}

class unknown_long_option final : public commandless_parse_error {
public:
    explicit unknown_long_option(std::string_view option) noexcept;
private:
    void print(std::ostream& stream) const override;

    std::string_view option;
};

unknown_long_option::unknown_long_option(std::string_view option) noexcept
    : option(option)
{
}

void unknown_long_option::print(std::ostream& stream) const
{
    stream << "Error: unknown option \"--" << option << '"';
}

class invalid_integer final : public commandless_parse_error {
public:
    explicit invalid_integer(std::string_view str) noexcept;

private:
    void print(std::ostream& stream) const override;

    std::string_view string;
};

invalid_integer::invalid_integer(std::string_view str) noexcept
    : string(str)
{
}

void invalid_integer::print(std::ostream& stream) const
{
    stream << "Error: \"" << string << "\" is not a valid integer";
}

class missing_required_value final : public commandless_parse_error {
public:
    explicit missing_required_value(std::string_view name) noexcept;
private:
    void print(std::ostream& stream) const override;

    std::string_view option_name;
};

missing_required_value::missing_required_value(std::string_view name) noexcept
    : option_name(name)
{
}

void missing_required_value::print(std::ostream& stream) const
{
    stream << "Error: option \"" << option_name << "\" requires a value, but none is present";
}

class no_command_passed final : public commandless_parse_error {
private:
    void print(std::ostream& stream) const override;
};

void no_command_passed::print(std::ostream& stream) const
{
    stream << "Error: no command name passed";
}

class unknown_command_name final : public commandless_parse_error {
public:
    explicit unknown_command_name(std::string_view name) noexcept;
private:
    void print(std::ostream& stream) const override;

    std::string_view command_name;
};

unknown_command_name::unknown_command_name(std::string_view name) noexcept
    : command_name(name)
{
}

void unknown_command_name::print(std::ostream& stream) const
{
    stream << "Error: unknown command name \"" << command_name << '"';
}

class missing_argument final : public commandful_parse_error {
public:
    using commandful_parse_error::commandful_parse_error;
private:
    void print(std::ostream& stream) const override;
};

void missing_argument::print(std::ostream& stream) const
{
    stream << "Error: missing value for a required argument";
}

class superfluous_arguments final : public commandful_parse_error {
public:
    explicit superfluous_arguments(command_cookie cookie, std::size_t argument_count) noexcept;
private:
    void print(std::ostream& stream) const noexcept override;

    std::size_t argument_count;
};

superfluous_arguments::superfluous_arguments(command_cookie cookie,
    std::size_t argument_count) noexcept
    : commandful_parse_error(cookie), argument_count(argument_count)
{
}

void superfluous_arguments::print(std::ostream& stream) const noexcept
{
    stream << argument_count << " superfluous argument(s) found";
}

class help_error final : public commandless_parse_error {
private:
    void print(std::ostream& stream) const override;
};

void help_error::print(std::ostream& stream) const
{
    stream << "General usage:";
}


using option_parser = void (*)(common_args&, std::string_view);

[[noreturn]] void show_help_message(common_args&, std::string_view)
{
    throw help_error();
}

void set_thread_count(common_args& destination, std::string_view arg)
{
    try {
        destination.thread_count = boost::lexical_cast<std::size_t>(arg.data(), arg.size());
    } catch(const boost::bad_lexical_cast&) {
        throw invalid_integer(arg);
    }
}

void set_verbose(common_args& destination, std::string_view)
{
    destination.verbose = true;
}

void unset_use_watcher(common_args& destination, std::string_view)
{
    destination.use_watcher = false;
}


struct option_spec {
    std::string_view name;
    bool wants_arg;
    option_parser parser;
    std::string_view description;
};

constexpr const option_spec option_specs[] = {
    {"help", false, show_help_message, "Show this message"},
    {"no-watcher", false, unset_use_watcher,
        "Disable watching for file changes done by other programs"},
    {"threads", true, set_thread_count, "Number of worker threads, or 0 for default"},
    {"verbose", false, set_verbose, "Enable verbose messages"},
};

std::pair<common_args, span<const std::string_view>> parse_common(span<const std::string_view> args)
{
    common_args result;
    std::size_t i = 1;
    const auto arg_count = args.size();
    for(; i < arg_count; ++i) {
        const auto arg = args[i];
        if(!boost::starts_with(arg, "--")) {
            // It's not an option, so pass it through as positional.
            break;
        }
        if(arg == "--") {
            // Ignore this argument and treat everything beyond it as
            // positional.
            ++i;
            break;
        }
        // We know it's an option at this point.
        const auto option_name_value = arg.substr(2);
        const auto equals_position = option_name_value.find('=');
        const auto option_name = (equals_position != std::string_view::npos)
            ? option_name_value.substr(0, equals_position)
            : option_name_value;
        const auto option_spec = std::find_if(std::begin(option_specs), std::end(option_specs),
            [&](const auto& spec) {return spec.name == option_name;});
        if(option_spec == std::end(option_specs)) {
            throw unknown_long_option(option_name);
        }
        if(!option_spec->wants_arg) {
            option_spec->parser(result, std::string_view());
        } else {
            const auto option_value = [&]{
                if(equals_position != std::string_view::npos) {
                    // We have the value already, just use it.
                    return option_name_value.substr(equals_position + 1);
                }
                // We need to use the next argument as the value.
                if(i + 1 >= arg_count) {
                    throw missing_required_value(option_spec->name);
                }
                ++i;
                return args[i];
            }();
            option_spec->parser(result, option_value);
        }
    }
    return {result, args.drop_first(i)};
}


const command_spec* find_command(std::string_view name);

template <typename T, typename... Fields>
struct command_parser_impl {
    static command parse(command_cookie cookie, span<const std::string_view> args);
};

template <typename T, typename... Fields>
command command_parser_impl<T, Fields...>::parse(command_cookie cookie,
    span<const std::string_view> args)
{
    T result;
    (..., (args = Fields::parse(cookie, result, args)));
    if(!args.empty()) {
        throw superfluous_arguments(cookie, args.size());
    }
    return result;
}

template <auto Field>
struct string_arg {
    template <typename T>
    static span<const std::string_view> parse(command_cookie cookie,
        T& result, span<const std::string_view> args);
};

template <auto Field>
template <typename T>
span<const std::string_view> string_arg<Field>::parse(command_cookie cookie,
    T& result, span<const std::string_view> args)
{
    if(args.empty()) {
        throw missing_argument(cookie);
    }
    (result.*Field) = args.front();
    return args.drop_first(1);
}

template <auto Field>
struct command_name_opt_arg {
    template <typename T>
    static span<const std::string_view> parse(command_cookie, T& result,
        span<const std::string_view> args);
};

template <auto Field>
template <typename T>
span<const std::string_view> command_name_opt_arg<Field>::parse(command_cookie, T& result,
    span<const std::string_view> args)
{
    if(args.empty()) {
        (result.*Field) = command_cookie();
        return args;
    }
    const auto command_name = args.front();
    const auto command = find_command(command_name);
    if(command == nullptr) {
        throw unknown_command_name(command_name);
    }
    (result.*Field) = command_to_cookie(*command);
    return args.drop_first(1);
}

constexpr command_spec command_specs[] = {
    {
        "diff",
        command_parser_impl<diff_command,
            string_arg<&diff_command::database_path>,
            string_arg<&diff_command::old_snapshot_name>,
            string_arg<&diff_command::new_snapshot_name>>::parse,
        "<DATABASE-PATH> <OLD-SNAPSHOT-NAME> <NEW-SNAPSHOT-NAME>",
        "Compare two snapshots",
        R"eof(Compare two snapshots for potential hash mismatches.

The first snapshot is assumed to be the older one, the second the newer one.

For every file path, compare the file hashes between the two given snapshots
only if the file's modification times between snapshots are equal. If they're
not, the file is assumed to have been modified, and thus there's no point
in comparing the hashes.

If a hash mismatch occurs, the file path, modification time and both old and
new hashes are printed, followed by hashes of the regions in that file whose
hashes don't match.

If any mismatch occurs, the command will fail. That condition can be
distinguished from other errors by the exit code, see '--help'.

If a snapshot name of either name doesn't exist, the command will fail.)eof"
    },
    {
        "fsck",
        command_parser_impl<fsck_command,
            string_arg<&fsck_command::database_path>>::parse,
        "<DATABASE-PATH>",
        "Check the database integrity",
        R"eof(Perform a thorough integrity check of the database file.

The use of this command is normally unnecessary, because SQLite is resilient
to crashes, including full system crashes. It's meant to be used only when
the database is suspected to be corrupt due to media failure, or due to
another program mishandling the database file.

This operation is very thorough and thus very costly.)eof"
    },
    {
        "full-diff",
        command_parser_impl<full_diff_command,
            string_arg<&full_diff_command::database_path>>::parse,
        "<DATABASE-PATH>",
        "Compare all consecutive snapshots",
        R"eof(Compare all consecutive pairs of snapshots for potential hash mismatches.

The snapshots are compared pairwise, starting from the oldest one by creation
time, i.e. if the oldest snapshot is A, and the newest snapshot is D,
the snapshot A will be compared with B, B will be compared with C, and C will
be compared with D.

For every file path, compare the file hashes between the two given snapshots
only if the file's modification times between snapshots are equal. If they're
not, the file is assumed to have been modified, and thus there's no point
in comparing the hashes.

If a hash mismatch occurs, the file path, modification time and both old and
new hashes are printed, followed by hashes of the regions in that file whose
hashes don't match.

If any mismatch occurs, the command will fail. That condition can be
distinguished from other errors by the exit code, see '--help'.

If a snapshot name of either name doesn't exist, the command will fail.)eof"
    },
    {
        "gc",
        command_parser_impl<gc_command,
            string_arg<&gc_command::database_path>>::parse,
        "<DATABASE-PATH>",
        "Vacuum a database",
        R"eof(Remove unused objects from the database and shrink it.

Normally removing snapshots from the database will not shrink it, the space
will just be internally marked as available for reuse. Moreover, some
records may be left in place in hope they'll become useful in the future.
This command does a full database scan to find and remove such records,
and then rebuilds the database so that unused space can be released to
the file system.

This operation is costly, especially on big databases, so it's recommended
to perform it only occasionally, after many cycles of insertions and
deletions.

Note that this operation will likely need to temporarily GROW the database,
so it will fail if the file system is short on free space.)eof"
    },
    {
        "help",
        command_parser_impl<help_command,
            command_name_opt_arg<&help_command::cookie>>::parse,
        "[<COMMAND>]",
        "Show detailed usage information",
        R"eof(If a command name is passed, bring up detailed information about
the speficied command.

If no command name is passed, print general usage information, just like
'--help'.)eof"
    },
    {
        "init",
        command_parser_impl<init_command,
            string_arg<&init_command::database_path>>::parse,
        "<PATH>",
        "Initialize a new database",
        R"eof(Create a new, empty database in the file specified by the given path.

If the file doesn't exist, it is created. If the file exists, the command will
fail.)eof"
    },
    {
        "list",
        command_parser_impl<list_command,
            string_arg<&list_command::database_path>>::parse,
        "<DATABASE-PATH>",
        "List all snapshots in a database",
        R"eof(List all snapshots in the given database file.

The data listed for each snapshot consists of its name, its creation time
and last update time.)eof",
    },
    {
        "new",
        command_parser_impl<new_command,
            string_arg<&new_command::database_path>,
            string_arg<&new_command::snapshot_name>>::parse,
        "<DATABASE-PATH> <SNAPSHOT-NAME>",
        "Create a new snapshot",
        R"eof(Create a new snapshot in the specified database.

The snapshot to be created will be filled with the hashes of the files
whose paths are specified on the standard input. The file paths shall be
UTF-8 strings separated by null characters (U+0000 NULL).

Only the contents of regular files are hashed. Directories, symlinks,
device nodes, etc. will be skipped.

If processing of any file fails, the error will be logged and the process
will continue. This situation is treated as a harmless error for the purpose
of determining the exit code.

The '--threads' option controls the number of threads used for hashing.
The default is to use a number derived from the number of active CPUs in the
system.

If the '--verbose' option is present, the name of each file will be printed
as it is being processed.

If a snapshot with the given name already exists, the command will fail.)eof"
    },
    {
        "new-empty",
        command_parser_impl<new_empty_command,
            string_arg<&new_empty_command::database_path>,
            string_arg<&new_empty_command::snapshot_name>>::parse,
        "<DATABASE-PATH> <SNAPSHOT-NAME>",
        "Create a new empty snapshot",
        R"eof(Create a new, empty snapshot in the specified database.

The snapshot is created as completely empty. File hashes can be added to it
later using the 'update' command.

If a snapshot with the given name already exists, the command will fail.)eof"
    },
    {
        "remove",
        command_parser_impl<remove_command,
            string_arg<&remove_command::database_path>,
            string_arg<&remove_command::snapshot_name>>::parse,
        "<DATABASE-PATH> <SNAPSHOT-NAME>",
        "Remove a snapshot with the given name",
        R"eof(Remove a snapshot with the give name from the specified database.

If there's no snapshot with the given name, the command will fail, but that
condition can be distinguished from other errors with the exit code, see
'--help'.

This command doesn't by itself free any disk space, it only marks file space
as available for reuse. See the 'gc' command for how reclaim that space.)eof"
    },
    {
        "update",
        command_parser_impl<update_command,
            string_arg<&update_command::database_path>,
            string_arg<&update_command::snapshot_name>>::parse,
        "<DATABASE-PATH> <SNAPSHOT-NAME>",
        "Update hashes in an existing snapshots",
        R"eof(Update the hashes in an existing snapshot.

The specified snapshot will be updated with the current hashes of the files
whose paths are specified on the standard input. The file paths shall be
UTF-8 strings separated by null characters (U+0000 NULL).

If the snapshot contains previous hashes of some of the files, these hashes
will be OVERWRITTEN.

Only the contents of regular files are hashed. Directories, symlinks,
device nodes, etc. will be skipped.

If processing of any file fails, the error will be logged and the process
will continue. This situation is treated as a harmless error for the purpose
of determining the exit code.

The '--threads' option controls the number of threads used for hashing.
The default is to use as many threads as there are active CPUs in the system.

If the '--verbose' option is present, the name of each file will be printed
as it is being processed.

If there's no snapshot with the given name, the command will fail.)eof"
    },
};

constexpr const command_spec& cookie_to_command(command_cookie cookie) noexcept
{
    return command_specs[cookie.get()];
}

constexpr command_cookie command_to_cookie(const command_spec& command) noexcept
{
    return command_cookie(static_cast<std::size_t>(&command - command_specs));
}

const command_spec* find_command(std::string_view name)
{
    const auto command_spec = std::find_if(std::begin(command_specs), std::end(command_specs),
        [&](const auto& spec) {return spec.name == name;});
    return (command_spec != std::end(command_specs)) ? command_spec : nullptr;
}

command parse_command(span<const std::string_view> args)
{
    if(args.empty()) {
        throw no_command_passed();
    }
    const auto command_name = args.front();
    const auto command = find_command(command_name);
    if(command == nullptr) {
        throw unknown_command_name(command_name);
    }
    return command->parser(command_to_cookie(*command), args.drop_first(1));
}

} // unnamed namespace

const char* parse_error::what() const noexcept
{
    return "argument parse error";
}

std::ostream& operator<<(std::ostream& stream, const parse_error& error)
{
    error.print(stream);
    return stream;
}


// Define them here so they're not usable outside of this file.
constexpr command_cookie::command_cookie() noexcept
    : id(SIZE_MAX)
{
}

constexpr command_cookie::command_cookie(std::size_t id) noexcept
    : id(id)
{
}

constexpr std::size_t command_cookie::get() const noexcept
{
    return id;
}

constexpr bool command_cookie::valid() const noexcept
{
    return id < std::size(command_specs);
}


struct exit_code_metadata {
    int value;
    std::string_view description;
};

constexpr exit_code_metadata exit_codes[] = {
#define DEFINE_EXIT_CODE_METADATA(_name, value, description) {(value), (description)},
    FILEHASH_FOR_EACH_EXIT_CODE(DEFINE_EXIT_CODE_METADATA)
#undef DEFINE_EXIT_CODE_METADATA
};


std::ostream& operator<<(std::ostream& stream, const usage& u)
{
    if(u.cookie.valid()) {
        const auto& command = cookie_to_command(u.cookie);
        stream << u.program_name << ' ' << command.name << ' ' << command.readable_arg_spec
            << "\n   " << command.short_description << "\n\n" << command.long_description;
    } else {
        stream << "usage: " << u.program_name
            << " [options...] [--] command [command args...]\n\nAllowed options:\n";
        for(const auto& option: option_specs) {
            stream << " --" << option.name << "\n     " << option.description << '\n';
        }
        stream << "\nCommands:\n";
        for(const auto& command: command_specs) {
            stream << ' ' << command.name << "\n   " << command.short_description << '\n';
        }
        stream << "\nTo get more information about a command, use " << u.program_name
            << " help <COMMAND>\n\n";
        stream << "Program exit codes and their meanings:\n";
        for(const auto& exit_code: exit_codes) {
            stream << ' ' << exit_code.value << ": " << exit_code.description << '\n';
        }
    }
    return stream;
}


args parse_args(span<const std::string_view> args)
{
    auto [common, rest] = parse_common(args);
    auto command = parse_command(rest);
    return {std::move(common), std::move(command)};
}

} // namespace filehash::args
