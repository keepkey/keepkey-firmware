#![no_std]

mod kklib;

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
use usbd_webusb::*;
use usb_device::prelude::*;

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
  KeepKeyBoard::set_led(LedAction::SetRedLed);
  KeepKeyBoard::set_led(LedAction::ClrGreenLed);

  let mut canvas = KeepKeyBoard::display_canvas();
  // canvas.set_constant_power(true);
  // let style = MonoTextStyle::new(&FONT_6X10, GrayColor::WHITE);
  let center = canvas.bounding_box().center();

  // canvas.draw_iter(IntoIter::new([Pixel(center, GrayColor::WHITE)])).unwrap();

  let mut text: heapless::String<512> = heapless::String::new();
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

  core::mem::drop(canvas);

  KeepKeyBoard::set_led(LedAction::ClrRedLed);
  KeepKeyBoard::set_led(LedAction::ClrGreenLed);

  let usb = KeepKeyBoard::usb();
  let mut winusb = kklib::usb::WinUsb::new(&usb, 1);
  let mut wusb = WebUsb::new(&usb, url_scheme::HTTPS, "beta.shapeshift.com");
  let mut kk_interface = kklib::usb::KeepKeyInterface::new(&usb, "KeepKey Interface");
  let mut kk_debug_link = kklib::usb::KeepKeyInterface::new(&usb, "KeepKey Debug Link Interface");

  let mut serial_number_buf: [u8; 24] = [0; 24];
  hex::encode_to_slice(KeepKeyBoard::serial_number(), &mut serial_number_buf).unwrap();
  let serial_number = core::str::from_utf8_mut(&mut serial_number_buf).unwrap();
  serial_number.make_ascii_uppercase();

  let mut usb_dev = UsbDeviceBuilder::new(&usb, UsbVidPid(0x2B24, 0x0002))
    .product("KeepKey")
    .manufacturer("KeyHodlers, LLC")
    .serial_number(serial_number)
    .max_packet_size_0(64)
    .build();

  loop {
    if usb_dev.poll(&mut [&mut winusb, &mut wusb, &mut kk_interface, &mut kk_debug_link]) {
      kk_interface.poll();
    }

    let mut text: heapless::String<512> = heapless::String::new();
    uwrite!(&mut text, "Hello, world! ({})", KeepKeyBoard::clock_ms()).unwrap();
    
    let mut canvas = KeepKeyBoard::display_canvas();
    canvas.clear(GrayColor::BLACK).unwrap();

    let text_box = TextBox::with_textbox_style(&text, bounds, character_style, textbox_style);
    let _ = LinearLayout::vertical(Chain::new(text_box))
      .with_alignment(horizontal::Center)
      .arrange()
      .align_to(&canvas.bounding_box(), horizontal::Center, vertical::Center)
      .draw(canvas.deref_mut())
      .unwrap();
  }
}

#[no_mangle]
pub extern "C" fn rust_button_handler(_pressed: bool) {
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
        uwrite!(&mut text, "{}", msg).ok()?;
      },
      #[cfg(debug_assertions)]
      ShutdownMessage::Panic(panic_info) => {
        match panic_info.payload().downcast_ref::<&str>() {
          None => uwrite!(&mut text, "Panic").ok()?,
          Some(payload) => uwrite!(&mut text, "Panic: {}", *payload).ok()?,
        }
        if let Some(location) = panic_info.location() {
          uwrite!(&mut text, "\n{}:{}:{}", location.file(), location.line(), location.column()).ok()?;
        }
      },
      #[cfg(not(debug_assertions))]
      ShutdownMessage::Panic => uwrite!(&mut text, "Panic").ok()?,
      // #[cfg(not(debug_assertions))]
      // ShutdownMessage::Panic(None) => uwrite!(&mut text, "Panic").ok()?,
      // #[cfg(not(debug_assertions))]
      // ShutdownMessage::Panic(Some(payload)) => uwrite!(&mut text, "Panic: {}", payload).ok()?,
    }
    Some(())
  })().map_or("Error Layout Failed", |_| &text);

  let character_style = MonoTextStyle::new(&FONT_6X10, GrayColor::WHITE);
  let textbox_style = TextBoxStyleBuilder::new()
      .height_mode(HeightMode::FitToText)
      .alignment(HorizontalAlignment::Center)
      .paragraph_spacing(6)
      .build();

  KeepKeyBoard::do_without_interrupts(|| {
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
  });
}
