#![no_std]

mod kklib;

use core::sync::atomic::{AtomicBool, Ordering};
use core::ops::DerefMut;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::*;
use embedded_graphics::mono_font::{ascii::FONT_6X10, MonoTextStyle};
use embedded_layout::{layout::linear::LinearLayout, prelude::*};
use embedded_text::{
  alignment::HorizontalAlignment,
  style::{HeightMode, TextBoxStyleBuilder},
  TextBox,
};
use kklib::{LedAction, KeepKeyBoard, ShutdownError, ShutdownMessage};
use ufmt::*;

#[no_mangle]
pub extern "C" fn rust_init() {
  let mut canvas = KeepKeyBoard::display_canvas();
  // canvas.set_constant_power(true);
  // let style = MonoTextStyle::new(&FONT_6X10, GrayColor::WHITE);
  let center = canvas.bounding_box().center();

  // canvas.draw_iter(IntoIter::new([Pixel(center, GrayColor::WHITE)])).unwrap();

  let mut text: heapless::String<32> = heapless::String::new();
  uwrite!(&mut text, "Hello, world! ({}, {})", center.x, center.y).unwrap();

  // Text::new(&text, center + Point::new(0, 10), style)
  //   .draw(canvas.deref_mut())
  //   .unwrap();
  // Rectangle::new(canvas.bounding_box().center() + Point::new(0, 20), Size::new(10, 10))
  //   .into_styled(PrimitiveStyleBuilder::new().fill_color(GrayColor::WHITE).build())
  //   .draw(canvas.deref_mut())
  //   .unwrap();

  let character_style = MonoTextStyle::new(&FONT_6X10, GrayColor::WHITE);
  let textbox_style = TextBoxStyleBuilder::new()
      .height_mode(HeightMode::FitToText)
      .alignment(HorizontalAlignment::Center)
      .paragraph_spacing(6)
      .build();

  canvas.clear(GrayColor::BLACK).unwrap();

  let bounds = Rectangle::new(Point::zero(), Size::new(canvas.bounding_box().size.width, 0));
  let text_box = TextBox::with_textbox_style(&text, bounds, character_style, textbox_style);
  let _ = LinearLayout::vertical(Chain::new(text_box))
    .with_alignment(horizontal::Center)
    .arrange()
    .align_to(&canvas.bounding_box(), horizontal::Center, vertical::Center)
    .draw(canvas.deref_mut())
    .unwrap();
}

#[no_mangle]
pub extern "C" fn rust_exec() {
  // for _ in 0..KeepKeyBoard::interrupt_lockout_count() {
    KeepKeyBoard::set_led(LedAction::SetGreenLed);
    KeepKeyBoard::delay_ms(100);
    KeepKeyBoard::set_led(LedAction::ClrGreenLed);
    KeepKeyBoard::delay_ms(100);
  // }
  // KeepKeyBoard::delay_ms(1000);
}

#[no_mangle]
pub extern "C" fn rust_usb_rx_callback(_ep: u8, _buf: *const u8, _len: usize) { }

static BUTTON_STATE: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern "C" fn rust_button_handler(pressed: bool) {
  let last_button_state = BUTTON_STATE.swap(pressed, Ordering::Relaxed);
  if last_button_state == pressed { return }

  // KeepKeyBoard::set_led(LedAction::TglRedLed);

  // let mut canvas = KeepKeyBoard::display_canvas();
  // canvas.set_constant_power(pressed);
  panic!("foobar");
}

#[no_mangle]
pub extern "C" fn rust_shutdown_hook(error_type: ShutdownError) {
  if error_type == ShutdownError::None {
    KeepKeyBoard::set_led(LedAction::ClrRedLed);
    KeepKeyBoard::set_led(LedAction::ClrGreenLed);
    return
  }
  layout_shutdown_message(ShutdownMessage::String(match error_type {
    ShutdownError::None => unreachable!(),
    ShutdownError::RustPanic => panic!(),
    ShutdownError::StackSmashingProtection => "Stack Smashing Detected",
    ShutdownError::ClockSecuritySystem => "Clock Glitch Detected",
    ShutdownError::MemoryFault => "Memory Protection Fault",
    ShutdownError::NonMaskableInterrupt => "Non-Maskable Interupt Detected",
    ShutdownError::ResetFailed => "Board Reset Failed",
    ShutdownError::FaultInjectionDefense => "Fault Injection Detected",
  }))
}

pub fn layout_shutdown_message(message: ShutdownMessage) {
  let mut text: heapless::String<512> = heapless::String::new();
  let text_ref: &str = (|| -> Option<()> {
    match message {
      ShutdownMessage::String(msg) => {
        KeepKeyBoard::set_led(LedAction::ClrRedLed);
        KeepKeyBoard::set_led(LedAction::ClrGreenLed);
        uwrite!(&mut text, "{}", msg).ok()?;
      },
      ShutdownMessage::PanicInfo(panic_info) => {
        match panic_info.payload().downcast_ref::<&str>() {
          None => {
            KeepKeyBoard::set_led(LedAction::SetRedLed);
            KeepKeyBoard::set_led(LedAction::ClrGreenLed);
            uwrite!(&mut text, "Panic").ok()?;
          }
          Some(payload) => {
            KeepKeyBoard::set_led(LedAction::SetRedLed);
            KeepKeyBoard::set_led(LedAction::SetGreenLed);
            uwrite!(&mut text, "Panic: {}", payload).ok()?;
          }
        }
        if let Some(location) = panic_info.location() {
          uwrite!(&mut text, "\n{}:{}:{}", location.file(), location.line(), location.column()).ok()?;
        }
      }
    }
    Some(())
  })().map_or("Error Layout Failed", |_| &text);

  let character_style = MonoTextStyle::new(&FONT_6X10, GrayColor::WHITE);
  let textbox_style = TextBoxStyleBuilder::new()
      .height_mode(HeightMode::FitToText)
      .alignment(HorizontalAlignment::Center)
      .paragraph_spacing(6)
      .build();

  let canvas = unsafe { KeepKeyBoard::display_canvas_leak() };
  canvas.clear(GrayColor::BLACK).unwrap();

  let bounds = Rectangle::new(Point::zero(), Size::new(canvas.bounding_box().size.width, 0));
  let text_box = TextBox::with_textbox_style(text_ref, bounds, character_style, textbox_style);
  let _ = LinearLayout::vertical(Chain::new(text_box))
    .with_alignment(horizontal::Center)
    .arrange()
    .align_to(&canvas.bounding_box(), horizontal::Center, vertical::Center)
    .draw(canvas)
    .unwrap();

  // We have to do this manually because we stole the canvas from its mutex earlier
  KeepKeyBoard::display_refresh(canvas);
}
