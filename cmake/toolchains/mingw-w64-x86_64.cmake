# MinGW-w64 cross-compile toolchain for the Windows emulator DLL (libkkemu.dll,
# x86_64). Lets us cross-build the Windows DLL from the existing macOS/Linux
# emulator build host — no Windows runner required.
#
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake \
#         -DKK_EMULATOR=ON -DKK_BUILD_DYLIB=ON -DKK_DEBUG_LINK=ON ...
#   cmake --build <dir> --target kkemulator_dylib
#
# Install MinGW: `brew install mingw-w64` (macOS) / `apt-get install mingw-w64`.
#
# Only the kkemulator_dylib target is meant to cross-compile. The standalone
# UDP `kkemu` binary is gated out on Windows (tools/emulator/CMakeLists.txt).

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)
find_program(CMAKE_C_COMPILER   NAMES ${TOOLCHAIN_PREFIX}-gcc)
find_program(CMAKE_CXX_COMPILER NAMES ${TOOLCHAIN_PREFIX}-g++)
find_program(CMAKE_RC_COMPILER  NAMES ${TOOLCHAIN_PREFIX}-windres)

if(NOT CMAKE_C_COMPILER)
  message(FATAL_ERROR
    "${TOOLCHAIN_PREFIX}-gcc not found. Install MinGW-w64 "
    "(brew install mingw-w64 / apt-get install mingw-w64).")
endif()

# Derive the target sysroot from the compiler location so this works across
# Homebrew versions and Linux package layouts.
get_filename_component(_kk_cc   "${CMAKE_C_COMPILER}" REALPATH)
get_filename_component(_kk_bin  "${_kk_cc}" DIRECTORY)
get_filename_component(_kk_root "${_kk_bin}/.." ABSOLUTE)
set(CMAKE_FIND_ROOT_PATH "${_kk_root}/${TOOLCHAIN_PREFIX}")

# Find host programs on the host; libraries/headers in the target sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
