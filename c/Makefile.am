# We're trying, with these cflags, to make a dynamic library which, when loaded, has no
# dependencies on PLT/GOT/whatever other stuff, which are normally accessed through TLS.
# We want to work even if TLS isn't set up.
AM_CFLAGS = -Wall -Werror -Wl,-znow -g -O0
AM_LDFLAGS = -Wl,-znow  -O0 -g

# Library
pkgconfig_DATA = rsyscall.pc
lib_LTLIBRARIES = librsyscall.la

librsyscall_la_SOURCES = src/rsyscall.c src/rsyscall_x86_64.S
include_HEADERS = src/rsyscall.h

# We want executables which are fully static and have no dependencies on libc; we aren't
# actually achieving that because we make libc calls in a few places. We don't want to
# achieve this by statically linking libc because that's unnecessary bloat - we're trying
# to replace libc anyway.
pkglibexec_PROGRAMS = rsyscall-server rsyscall-bootstrap rsyscall-stdin-bootstrap rsyscall-unix-stub

rsyscall_stdin_bootstrap_SOURCES = src/rsyscall_stdin_bootstrap.c
rsyscall_stdin_bootstrap_LDADD = librsyscall.la

rsyscall_server_SOURCES = src/rsyscall_server_main.c
rsyscall_server_LDADD = librsyscall.la

rsyscall_bootstrap_SOURCES = src/rsyscall_bootstrap.c
rsyscall_bootstrap_LDADD = librsyscall.la

rsyscall_unix_stub_SOURCES = src/rsyscall_unix_stub.c
rsyscall_unix_stub_LDADD = librsyscall.la

noinst_PROGRAMS = remote_cat
remote_cat_SOURCES = src/remote_cat.c
