set(sources
    keepkey_main.c
    startup.s
    header.s)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/keepkey.ld)

set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  link_directories(${CMAKE_SOURCE_DIR}/keepkey-rs/target/thumbv7m-none-eabi/debug)
else()
  link_directories(${CMAKE_SOURCE_DIR}/keepkey-rs/target/thumbv7m-none-eabi/release)
endif()

set(LINK_FLAGS
    kkfirmware
    kkboard
    -lopencm3_stm32f2
    -lc
    -lm)

add_executable(firmware.keepkey.elf ${sources})
target_link_libraries(firmware.keepkey.elf
    kkfirmware
    kkboard
    kkrand
    -lopencm3_stm32f2
    -lc
    -lm
    keepkey_rs
    kkfirmware
    kkboard
    kkrand)
add_custom_command(TARGET firmware.keepkey.elf
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
        ${CMAKE_BINARY_DIR}/bin/firmware.keepkey.elf
        ${CMAKE_BINARY_DIR}/bin/firmware.keepkey.bin)
