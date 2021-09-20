use usb_device::class_prelude::*;
use usb_device::Result;
use usb_device::descriptor;

pub struct KeepKeyInterface<'a, B: UsbBus> {
  pub interface_name: &'a str,
  pub interface_num: InterfaceNumber,
  interface_str: StringIndex,
  ep_interrupt_in: EndpointIn<'a, B>,
  ep_interrupt_out: EndpointOut<'a, B>,
  interrupt_buf: [u8; 64],
  expect_interrupt_in_complete: bool,
  expect_interrupt_out: bool,
}

impl<B: UsbBus> KeepKeyInterface<'_, B> {
  pub fn new<'a>(alloc: &'a UsbBusAllocator<B>, interface_name: &'a str) -> KeepKeyInterface<'a, B> {
    KeepKeyInterface {
      interface_name: interface_name,
      interface_str: alloc.string(),
      interface_num: alloc.interface(),
      ep_interrupt_in: alloc.interrupt(64, 1),
      ep_interrupt_out: alloc.interrupt(64, 1),
      interrupt_buf: [0; 64],
      expect_interrupt_in_complete: false,
      expect_interrupt_out: false,
    }
  }

  /// Must be called after polling the UsbDevice.
  pub fn poll(&mut self) {
    match self.ep_interrupt_out.read(&mut self.interrupt_buf) {
      Ok(count) => {
        if self.expect_interrupt_out {
          self.expect_interrupt_out = false;
        } else {
          panic!("unexpectedly read data from interrupt out endpoint");
        }

        self.ep_interrupt_in.write(&self.interrupt_buf[0..count])
          .expect("interrupt write");

        self.expect_interrupt_in_complete = true;
      },
      Err(UsbError::WouldBlock) => { },
      Err(err) => panic!("interrupt read {:?}", err),
    };
  }
}

impl<B: UsbBus> UsbClass<B> for KeepKeyInterface<'_, B> {
  fn reset(&mut self) {
    self.expect_interrupt_in_complete = false;
    self.expect_interrupt_out = false;
  }

  fn get_configuration_descriptors(&self, writer: &mut DescriptorWriter) -> Result<()> {
    writer.interface_alt(self.interface_num, 0, 0xff, 0x00, 0x00, Some(self.interface_str))?;
    writer.endpoint(&self.ep_interrupt_in)?;
    writer.endpoint(&self.ep_interrupt_out)?;

    Ok(())
  }

  fn get_string(&self, index: StringIndex, lang_id: u16) -> Option<&str> {
    if lang_id == descriptor::lang_id::ENGLISH_US {
      if index == self.interface_str {
        return Some(self.interface_name);
      }
    }

    None
  }

  fn endpoint_in_complete(&mut self, addr: EndpointAddress) {
    if addr == self.ep_interrupt_in.address() {
      if self.expect_interrupt_in_complete {
        self.expect_interrupt_in_complete = false;
      } else {
        panic!("unexpected endpoint_in_complete");
      }
    }
  }

  fn endpoint_out(&mut self, addr: EndpointAddress) {
    if addr == self.ep_interrupt_out.address() {
      self.expect_interrupt_out = true;
    }
  }
}
