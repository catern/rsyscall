## Process this file with automake to produce Makefile.in
AM_CFLAGS = -Wall -Werror -Wl,-znow -fno-plt -g -O0
AM_LDFLAGS = -Wl,-znow  -O0 -g

# Library
pkgconfig_DATA = rsyscall.pc
lib_LTLIBRARIES = librsyscall.la

librsyscall_la_SOURCES = src/rsyscall.c src/rsyscall_x86_64.S
include_HEADERS = src/rsyscall.h

# Programs
pkglibexec_PROGRAMS = rsyscall-server socket-binder
rsyscall_server_SOURCES = src/rsyscall_server_main.c
rsyscall_server_LDADD = librsyscall.la

socket_binder_SOURCES = src/socket_binder.c

bin_PROGRAMS = cat remote_cat
cat_SOURCES = src/cat.c
remote_cat_SOURCES = src/remote_cat.c

# remote_in_to_out_SOURCES = src/remote_in_to_out_main.c
# in_to_remote_out_SOURCES = src/in_to_remote_out_main.c
