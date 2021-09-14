cmake_minimum_required(VERSION 3.7.2)

project(KeepKeyFirmware

        VERSION 8.0.0

        LANGUAGES C CXX ASM)

option(KK_EMULATOR "Build the emulator" OFF)
option(KK_DEBUG_LINK "Build with debug-link enabled" OFF)
set(LIBOPENCM3_PATH /root/libopencm3 CACHE PATH "Path to an already-built libopencm3")
set(CMAKE_DEBUG_POSTFIX CACHE STRING "Debug library name postfix")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules/")
include(GetGitRevisionDescription)
get_git_head_revision(GIT_REFSPEC GIT_SHA1)

if(${KK_EMULATOR})
  add_definitions(-DEMULATOR)
endif()

add_definitions(-DSTM32F2=1)

add_definitions(-DMAJOR_VERSION=${PROJECT_VERSION_MAJOR})
add_definitions(-DMINOR_VERSION=${PROJECT_VERSION_MINOR})
add_definitions(-DPATCH_VERSION=${PROJECT_VERSION_PATCH})

if(${KK_DEBUG_LINK})
  add_definitions(-DDEBUG_LINK=1)
else()
  add_definitions(-DDEBUG_LINK=0)
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  add_definitions(-DDEBUG_ON)
elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release" OR
       "${CMAKE_BUILD_TYPE}" STREQUAL "MinSizeRel" OR
       "${CMAKE_BUILD_TYPE}" STREQUAL "")
  add_definitions(-DNDEBUG)
else()
  message(ERROR "Must pick Release *or* Debug CMAKE_BUILD_TYPE")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(NOT ${KK_EMULATOR})
  link_directories(${LIBOPENCM3_PATH}/lib)
  include_directories(${LIBOPENCM3_PATH}/include)

  # Dummy empty libraries for stack smashing protection support, since we
  # implement __stack_chk_guard and __stack_chk_fail ourselves.
  file(WRITE ${CMAKE_BINARY_DIR}/ssp.c "")
  add_library(ssp ${CMAKE_BINARY_DIR}/ssp.c)
  add_library(ssp_nonshared ${CMAKE_BINARY_DIR}/ssp.c)
  set_property(TARGET ssp PROPERTY LINKER_LANGUAGE CXX)
  set_property(TARGET ssp_nonshared PROPERTY LINKER_LANGUAGE CXX)
  set_target_properties(ssp ssp_nonshared
      PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

add_subdirectory(lib)
add_subdirectory(tools)
