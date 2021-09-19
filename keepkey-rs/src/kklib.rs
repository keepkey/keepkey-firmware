#![allow(dead_code)]
mod bindings;
pub mod board;
pub mod canvas_mutex_guard;
pub mod firmware;
pub mod rand;
pub mod types;

use core::panic::PanicInfo;

pub use board::*;
pub use canvas_mutex_guard::*;
pub use firmware::*;
pub use rand::*;
pub use types::*;

pub enum ShutdownMessage<'a> {
  String(&'a str),
  PanicInfo(&'a PanicInfo<'a>),
}

#[panic_handler]
fn handle_panic(info: &PanicInfo) -> ! {
  KeepKeyBoard::do_without_interrupts(|| {
    super::layout_shutdown_message(super::ShutdownMessage::PanicInfo(info));
    KeepKeyBoard::shutdown_with_error(ShutdownError::RustPanic);
  });
  unreachable!();
}
