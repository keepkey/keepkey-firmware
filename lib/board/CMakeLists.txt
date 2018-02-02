set(sources
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
    msg_dispatch.c
    pin.c
    resources.c
    rng.c
    timer.c
    usb_driver.c)

if(NOT ${KK_EMULATOR})
  enable_language(ASM)
  set(sources ${sources} startup.s)
endif()

include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include)

add_library(kkboard ${sources})
add_dependencies(kkboard kktransport kktransport.pb)

add_library(kkboard.keepkey ${CMAKE_CURRENT_SOURCE_DIR}/whitelabel/keepkey/logo.c)
add_library(kkboard.salt ${CMAKE_CURRENT_SOURCE_DIR}/whitelabel/salt/logo.c)
