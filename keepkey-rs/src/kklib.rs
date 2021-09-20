#![allow(dead_code)]
mod bindings;
pub mod board;
pub mod canvas_mutex_guard;
pub mod firmware;
pub mod rand;
pub mod types;
pub mod usb;

use core::panic::PanicInfo;

pub use board::*;
pub use canvas_mutex_guard::*;
pub use firmware::*;
pub use rand::*;
pub use types::*;

pub enum ShutdownMessage<'a> {
  String(&'a str),
  #[cfg(debug_assertions)]
  Panic(&'a PanicInfo<'a>),
  #[cfg(not(debug_assertions))]
  Panic,
  // #[cfg(not(debug_assertions))]
  // Panic(Option<&'a str>),
}

#[cfg(debug_assertions)]
#[panic_handler]
fn handle_panic(info: &PanicInfo) -> ! {
  KeepKeyBoard::do_without_interrupts(|| {
    super::layout_shutdown_message(ShutdownMessage::Panic(info));
    KeepKeyBoard::shutdown_with_error(ShutdownError::RustPanic);
  });
  unreachable!();
}

#[cfg(not(debug_assertions))]
#[panic_handler]
fn handle_panic(_info: &PanicInfo) -> ! {
  KeepKeyBoard::do_without_interrupts(|| {
    // Unfortunately, touching the PanicInfo payload causes the compiler to build in all the location info we
    // don't want bloating a release version.
    // super::layout_shutdown_message(ShutdownMessage::Panic(info.payload().downcast_ref::<&str>().map(|x| *x)));
    super::layout_shutdown_message(ShutdownMessage::Panic);
    KeepKeyBoard::shutdown_with_error(ShutdownError::RustPanic);
  });
  unreachable!();
}
