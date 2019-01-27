# Copyright 2019 Fanael Linithien
#
# This file is part of filehash-v2.
#
# filehash-v2 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# filehash-v2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with filehash-v2.  If not, see <https://www.gnu.org/licenses/>.
project('filehash-v2', 'cpp', version: '0.2', license: 'GPL3+',
        default_options: ['cpp_std=c++17'],
        meson_version: '>=0.48.0')

cxx = meson.get_compiler('cpp')

boost_dep = dependency('boost')
sqlite_dep = dependency('sqlite3')
threads_dep = dependency('threads')

defines = []
common_args = []
link_args = []

useful_warnings = [
  '-pedantic',
  '-pedantic-errors',
  '-Wall',
  '-Wextra',
  '-Wconversion',
  '-Wsign-conversion',
  '-Wstrict-aliasing',
  '-Wstrict-overflow=4',
  '-Wcast-align',
  '-Wold-style-cast',
  '-Wzero-as-null-pointer-constant',
]

foreach flag: useful_warnings
  if cxx.has_argument(flag)
    common_args += flag
  endif
endforeach

use_pie = get_option('use_pie')
if use_pie and cxx.has_argument('-fno-plt')
  common_args += '-fno-plt'
endif

if get_option('use_relro')
  if cxx.has_link_argument('-Wl,-z,relro,-z,now')
    link_args += '-Wl,-z,relro,-z,now'
  endif
endif

if get_option('use_lto')
  if cxx.has_argument('-flto')
    common_args += '-flto'
    link_args += '-O3'
    if cxx.has_argument('-flto-partition=one')
      common_args += '-flto-partition=one'
    elif cxx.has_argument('-flto-partition=none')
      common_args += '-flto-partition=none'
    endif
  else
    warning('Don\'t know how to enable LTO on this compiler, building without')
  endif
endif

if get_option('use_stack_protector')
  if cxx.has_argument('-fstack-protector-strong')
    common_args += '-fstack-protector-strong'
  elif cxx.has_argument('-fstack-protector-all')
    common_args += '-fstack-protector-all'
  elif cxx.has_argument('-fstack-protector')
    common_args += '-fstack-protector'
  else
    warning('Don\'t know how to enable stack protector on this compiler, building without')
  endif
endif

if cxx.has_argument('-fstack-clash-protection')
  common_args += '-fstack-clash-protection'
endif

if get_option('use_gc_sections')
  if cxx.has_link_argument('-Wl,--gc-sections')
    link_args += '-Wl,--gc-sections'
    if cxx.has_argument('-fdata-sections')
      common_args += '-fdata-sections'
    endif
    if cxx.has_argument('-ffunction-sections')
      common_args += '-ffunction-sections'
    endif
  endif
endif

defines += '-D_FILE_OFFSET_BITS=64'
defines += '-D_FORTIFY_SOURCE=2'

if cxx.has_header_symbol('features.h', '__GLIBC__')
  defines += '-D_GNU_SOURCE'
endif

if cxx.has_header_symbol('cstddef', '__GLIBCXX__')
  # Gets rid of unnecessary runtime checks if threads are enabled.
  # We know they are.
  defines += '-D_GLIBCXX_GTHREAD_USE_WEAK=0'
endif

sources = [
  'src/arg-parse.cc',
  'src/blake2sp4.cc',
  'src/compiler.cc',
  'src/database.cc',
  'src/file-descriptor.cc',
  'src/file-watcher-common.cc',
  'src/hash-engine.cc',
  'src/main.cc',
  'src/sqlite.cc',
  'src/syscall-error.cc',
]

conf_data = configuration_data()

# NB: need to test for kqueue before inotify because FreeBSD for example has
# inotify headers, but inotify fails to link.
if get_option('use_dummy_watcher')
  conf_data.set('FILEHASH_DUMMY_WATCHER_ONLY', true)
elif cxx.has_header_symbol('sys/event.h', 'kqueue')
  sources += 'src/file-watcher-kqueue.cc'
elif cxx.has_header_symbol('sys/inotify.h', 'inotify_init1')
  sources += 'src/file-watcher-inotify.cc'
else
  error(
    'No file watcher API supported on this system, use -Duse_dummy_watcher=true to build w/o one.')
endif

# It's always provided as an alternative.
sources += 'src/file-watcher-dummy.cc'

configure_file(input: 'src/config.hh.in',
               output: 'config.hh',
               configuration: conf_data)
configuration_dir = include_directories('.')

executable('filehash-v2', sources,
           dependencies: [boost_dep, sqlite_dep, threads_dep],
           install: true,
           gnu_symbol_visibility: 'inlineshidden',
           pie: use_pie,
           implicit_include_directories: false,
           include_directories: configuration_dir,
           cpp_args: defines + common_args,
           link_args: common_args + link_args)
