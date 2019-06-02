## Process this file with automake to produce Makefile.in
AM_CFLAGS = -Wall -Werror -Wl,-znow -fno-plt -g -O0
AM_LDFLAGS = -Wl,-znow  -O0 -g

# Library
pkgconfig_DATA = rsyscall.pc
lib_LTLIBRARIES = librsyscall.la

librsyscall_la_SOURCES = src/rsyscall.c src/rsyscall_x86_64.S
include_HEADERS = src/rsyscall.h

# Programs
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
