cmake_minimum_required(VERSION 3.20)
project(fire_storm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(fire_storm src/main.cpp)

target_compile_options(fire_storm PRIVATE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)

# Debug builds catch out-of-bounds reads and undefined behaviour at runtime,
# which matters when parsing lengths taken from untrusted network data.
option(FIRE_STORM_SANITIZE "Enable AddressSanitizer + UBSan" OFF)
if(FIRE_STORM_SANITIZE)
  target_compile_options(fire_storm PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(fire_storm PRIVATE -fsanitize=address,undefined)
endif()
