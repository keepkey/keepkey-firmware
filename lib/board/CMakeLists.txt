set(sources
    check_bootloader.c
    confirm_sm.c
    draw.c
    font.c
    keepkey_board.c
    keepkey_button.c
    keepkey_display.c
    keepkey_flash.c
    keepkey_leds.c
    keepkey_usart.c
    layout.c
    memory.c
    mmhusr.c
    messages.c
    pin.c
    resources.c
    signatures.c
    supervise.c
    timer.c
    u2f.c
    udp.c
    usb.c
    usb21_standard.c
    util.c
    variant.c
    webusb.c
    winusb.c)

include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto
  ${CMAKE_CURRENT_SOURCE_DIR})

add_library(kkboard ${sources})
add_dependencies(kkboard kktransport kktransport.pb)

add_library(kkboard.keepkey
    ${CMAKE_CURRENT_SOURCE_DIR}/variant/keepkey/resources.c)
add_library(kkboard.mfr
    ${CMAKE_CURRENT_SOURCE_DIR}/variant/mfr/memory.c
    ${CMAKE_CURRENT_SOURCE_DIR}/variant/mfr/resources.c)
