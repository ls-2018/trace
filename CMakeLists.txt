cmake_minimum_required(VERSION 3.28.3)
project(trace C)

set(CMAKE_C_STANDARD 11)
include_directories("./ebpf/headers")
message(STATUS "Current architecture: ${CMAKE_SYSTEM_PROCESSOR}")

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_definitions("-D__TARGET_ARCH_x86")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target amd64-linux-gnu")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    add_definitions("-D__TARGET_ARCH_arm64")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target arm64-linux-gnu")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    add_definitions("-D__TARGET_ARCH_arm64")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target arm64-linux-gnu")
else ()
    message(STATUS "This is an unknown processor architecture.")
endif ()

add_library(ebpf-nftrace
        ./ebpf/src/kernel/01_kprobe.bpf.c
        ./ebpf/src/kernel/02_kretprobe.bpf.c
)

add_executable(extract_btf cases/extract_btf.c)
add_executable(expect cases/expect.c)