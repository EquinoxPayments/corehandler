cmake_minimum_required (VERSION 2.8.0)

project (corehandler)

# set (CMAKE_C_COMPILER "arm gcc")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wno-switch -D_XOPEN_SOURCE=600 -D_BSD_SOURCE")

add_executable (
    corehandler
    src/config.h
    src/main.c
    src/proc.c
    src/proc.h
    src/unwind.c
    src/unwind.h
    src/util.c
    src/util.h
    src/version.h
    src/xmalloc.c
    src/xmalloc.h
)

