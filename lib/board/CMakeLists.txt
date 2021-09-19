include(CheckSymbolExists)

set(sources
    keepkey_board.c
    keepkey_button.c
    keepkey_display.c
    keepkey_flash.c
    keepkey_leds.c
    memory.c
    mmhusr.c
    pin.c
    reexport.c
    supervise.c
    timer.c
    usb.c
    util.c)

if(${KK_EMULATOR})
    set(sources ${sources}
        udp.c)
else()
    set(sources ${sources}
        otp.c
        usb21_standard.c
        webusb.c
        winusb.c)
endif()

include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR})

add_library(kkboard ${sources})
