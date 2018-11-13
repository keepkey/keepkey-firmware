load_cache(docker.cmake)

# Tell cmake that we're cross compiling for baremetal
set(CMAKE_SYSTEM_NAME Generic CACHE STRING "")
set(CMAKE_CROSSCOMPILING 1)

include(CMakeForceCompiler)

# The sysroot. Just assume the one installed in the docker image for now
set(CMAKE_SYSROOT /usr/local/arm-none-eabi CACHE PATH "")

set(CMAKE_C_COMPILER arm-none-eabi-gcc CACHE FILEPATH "")
set(CMAKE_CXX_COMPILER arm-none-eabi-g++ CACHE FILEPATH "")

# FIXME: teach cmake how to do compiler tests on baremetal
set(CMAKE_C_COMPILER_WORKS True CACHE BOOL "")
set(CMAKE_CXX_COMPILER_WORKS True CACHE BOOL "")

set(ARCH_FLAGS
    "-mthumb \
    -mcpu=cortex-m3 \
    -msoft-float \
    -ffunction-sections \
    -fdata-sections \
    -fno-common \
    -fstack-protector-all" CACHE STRING "")

set(WARN_FLAGS
    "-Wall \
    -Wextra \
    -Wformat \
    -Wformat-nonliteral \
    -Wformat-security \
    -Wimplicit-function-declaration \
    -Winit-self \
    -Wmultichar \
    -Wpointer-arith \
    -Wredundant-decls \
    -Wreturn-type \
    -Wshadow \
    -Wsign-compare \
    -Wstrict-prototypes \
    -Wundef \
    -Wuninitialized \
    -Werror")

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(OPT_FLAGS "-O1 -g" CACHE STRING "")
elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release" OR
       "${CMAKE_BUILD_TYPE}" STREQUAL "")
  set(OPT_FLAGS "-Os" CACHE STRING "")
endif()

set(CMAKE_C_FLAGS "${ARCH_FLAGS} -std=gnu99 ${OPT_FLAGS} ${WARN_FLAGS}" CACHE STRING "")
set(CMAKE_CXX_FLAGS "${ARCH_FLAGS} -std=gnu++11 ${OPT_FLAGS} ${WARN_FLAGS} \
    -fno-exceptions \
    -fno-rtti \
    -fno-threadsafe-statics \
    -fuse-cxa-atexit \
    -Woverloaded-virtual \
    -Weffc++" CACHE STRING "")

set(CMAKE_ASM_FLAGS "-mcpu=cortex-m3 \
    -mthumb \
    -x assembler-with-cpp \
    -gdwarf-2" CACHE STRING "")

set(CMAKE_EXE_LINKER_FLAGS
    "-mthumb \
    -mcpu=cortex-m3 \
    -nostartfiles \
    -msoft-float \
    -specs=nosys.specs \
    -Wl,--gc-sections" CACHE STRING "")
