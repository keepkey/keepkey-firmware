load_cache(docker.cmake)

# Tell cmake that we're cross compiling for baremetal
set(CMAKE_SYSTEM_NAME Generic CACHE STRING "")
set(CMAKE_CROSSCOMPILING 1)

include(CMakeForceCompiler)

# The sysroot. Just assume the one installed in the docker image for now
set(CMAKE_SYSROOT /usr/arm-none-eabi CACHE PATH "")

set(CMAKE_C_COMPILER arm-none-eabi-gcc CACHE FILEPATH "")
set(CMAKE_CXX_COMPILER arm-none-eabi-g++ CACHE FILEPATH "")

# FIXME: teach cmake how to do compiler tests on baremetal
set(CMAKE_C_COMPILER_WORKS True CACHE BOOL "")
set(CMAKE_CXX_COMPILER_WORKS True CACHE BOOL "")

set(floatarch -mfloat-abi=soft)
set(fpu -mfpu=fpv4-sp-d16)
set(cpu -mcpu=cortex-m4)


set(ARCH_FLAGS
    "-mthumb \
    ${cpu} \
    ${fpu} \
    ${floatarch} \
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


set(KK_C_FLAGS "${ARCH_FLAGS} -std=gnu99 ${WARN_FLAGS}" CACHE STRING "")
set(KK_CXX_FLAGS "${ARCH_FLAGS} -std=gnu++11 ${WARN_FLAGS} \
    -fno-exceptions \
    -fno-rtti \
    -fno-threadsafe-statics \
    -fuse-cxa-atexit \
    -Woverloaded-virtual \
    -Weffc++" CACHE STRING "")

set(CMAKE_C_FLAGS_DEBUG "${KK_C_FLAGS} -Os -g" CACHE STRING "")
set(CMAKE_C_FLAGS_MINSIZEREL "${KK_C_FLAGS} -Os" CACHE STRING "")
set(CMAKE_C_FLAGS_RELEASE "${KK_C_FLAGS} -Os" CACHE STRING "")
set(CMAKE_CXX_FLAGS_DEBUG "${KK_CXX_FLAGS} -Os -g" CACHE STRING "")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${KK_CXX_FLAGS} -Os" CACHE STRING "")
set(CMAKE_CXX_FLAGS_RELEASE "${KK_CXX_FLAGS} -Os" CACHE STRING "")

set(CMAKE_ASM_FLAGS "${cpu} \
    -mthumb \
    -x assembler-with-cpp \
    -gdwarf-2" CACHE STRING "")

set(CMAKE_EXE_LINKER_FLAGS
    "-mthumb \
    ${cpu} \
    ${fpu} \
    -nostartfiles \
    ${floatarch} \
    -specs=nosys.specs \
    -Wl,--gc-sections" CACHE STRING "")
