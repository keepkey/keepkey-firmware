include(CheckSymbolExists)

set(sources
    check_bootloader.c
    common.c
    confirm_sm.c
    draw.c
    font.c
    keepkey_board.c
    keepkey_button.c
    keepkey_flash.c
    keepkey_leds.c
    keepkey_usart.c
    layout.c
    memory.c
    memcmp_s.c
    mmhusr.c
    messages.c
    pin.c
    resources.c
    signatures.c
    supervise.c
    timer.c
    usb.c
    util.c
    variant.c)

if("${DEVDEBUG}" STREQUAL "true")
  set(sources ${sources}
    keepkey_spidisplay.c)
    if("${TWODISP}" STREQUAL "true")
      set(sources ${sources}
      ssd1351/ssd1351.c
      ssd1351/fonts.c)
    endif()
    
else()
  set(sources ${sources}
    keepkey_display.c)
endif()

check_symbol_exists(strlcpy "string.h" KK_HAVE_STRLCPY)
if(NOT KK_HAVE_STRLCPY)
    set(sources ${sources} strlcpy.c)
endif()

check_symbol_exists(strlcat "string.h" KK_HAVE_STRLCAT)
if(NOT KK_HAVE_STRLCAT)
    set(sources ${sources} strlcat.c)
endif()

if(${KK_EMULATOR})
    set(sources ${sources}
        udp.c)
else()
    set(sources ${sources}
        otp.c
        usb21_standard.c
        webusb.c
        winusb.c
        memcmp_cst.S)
endif()

include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto
  ${CMAKE_CURRENT_SOURCE_DIR})

add_library(kkboard ${sources})
add_dependencies(kkboard kktransport kktransport.pb)

add_library(kkboard.keepkey
    ${CMAKE_CURRENT_SOURCE_DIR}/variant/keepkey/resources.c)
