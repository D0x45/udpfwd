cmake_minimum_required(VERSION 3.10)
project(udpfwd)

set(CMAKE_BUILD_TYPE Release)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS_DEBUG "-Wall -Wpedantic -g")

set(CMAKE_C_FLAGS_RELEASE "-Wall -Wpedantic -O2")

file(GLOB SOURCES "src/*.c")
add_executable(udpfwd ${SOURCES})

# winsock2 library
target_link_libraries(udpfwd ws2_32)

set(LIBUV_BUILD_SHARED OFF CACHE BOOL "Build libuv as a static library" FORCE)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(LIBUV_BUILD_TESTS OFF CACHE BOOL "Disable testing")
endif()

include_directories(lib/libuv/include)
add_subdirectory(lib/libuv)
target_link_libraries(udpfwd uv_a)
