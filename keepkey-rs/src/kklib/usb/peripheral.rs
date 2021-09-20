use stm32f2::stm32f215 as pac;
use synopsys_usb_otg::{UsbPeripheral};

pub use synopsys_usb_otg::UsbBus;
pub use usb_device::bus::UsbBusAllocator;

pub struct Usb ();

unsafe impl UsbPeripheral for Usb {
  const REGISTERS: *const () = pac::OTG_FS_GLOBAL::ptr() as *const ();
  const HIGH_SPEED: bool = false;
  const FIFO_DEPTH_WORDS: usize = 320;
  const ENDPOINT_COUNT: usize = 4;

  fn enable() { }
  fn ahb_frequency_hz(&self) -> u32 { 120_000_000 }
}
