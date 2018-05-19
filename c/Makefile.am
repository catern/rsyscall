## Process this file with automake to produce Makefile.in
AM_CFLAGS = -Wall -Werror

# "Header-only" library, since it only declares structs
pkgconfig_DATA = rsyscall.pc
include_HEADERS = src/rsyscall.h

# Programs
bin_PROGRAMS = rsyscall_server cat remote_cat
# bin_PROGRAMS = rsyscall_server cat remote_in_to_out in_to_remote_out
rsyscall_server_SOURCES = src/rsyscall_server_main.c
cat_SOURCES = src/cat.c
remote_cat_SOURCES = src/remote_cat.c
# remote_in_to_out_SOURCES = src/remote_in_to_out_main.c
# in_to_remote_out_SOURCES = src/in_to_remote_out_main.c
