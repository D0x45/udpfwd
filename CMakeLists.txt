cmake_minimum_required(VERSION 3.10)
project(udpfwd)

set(CMAKE_C_STANDARD "99")
set(CMAKE_C_FLAGS "-Wall -Wpedantic")

set(CMAKE_C_FLAGS_DEBUG "-g ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O2 ${CMAKE_C_FLAGS}")

file(GLOB SOURCES "src/*.c")
add_executable(udpfwd ${SOURCES})

if(WIN32)
    target_link_libraries(udpfwd ws2_32)
endif()

set(LIBUV_BUILD_SHARED OFF CACHE BOOL "Build libuv as a static library" FORCE)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(LIBUV_BUILD_TESTS OFF CACHE BOOL "Disable testing")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_definitions(-DDEBUG)
endif()

include_directories(lib/libuv/include)
add_subdirectory(lib/libuv)

include_directories(lib/libstun/include)
add_subdirectory(lib/libstun)

target_link_libraries(udpfwd uv_a)
target_link_libraries(udpfwd stun)
