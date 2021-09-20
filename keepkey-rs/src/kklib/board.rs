use super::canvas_mutex_guard::CanvasMutexGuard;
use super::bindings;
use super::types::{Allocation, Canvas, ShutdownError, LedAction};
use super::usb::{Usb, UsbBus, UsbBusAllocator};

pub struct KeepKeyBoard {
  _0: (),
}

static CANVAS: spin::Once<spin::Mutex<Canvas>> = spin::Once::new();
static mut EP_MEMORY: [u32; 1024] = [0; 1024];
static USB_BUS_ALLOCATOR: spin::Once<spin::Mutex<UsbBusAllocator<UsbBus<Usb>>>> = spin::Once::new();

impl KeepKeyBoard {
  pub fn shutdown_with_error(error: ShutdownError) -> ! { unsafe { bindings::shutdown_with_error(error); } }
  pub fn board_reset() -> ! { unsafe { bindings::board_reset() } }

  pub fn serial_number() -> [u8; 12] {
    let mut out = [0; 12];
    unsafe { bindings::desig_get_unique_id2(&mut out as *mut u8 as *mut u32); }
    return out;
  }

  pub fn fi_defense_delay() { unsafe { bindings::fi_defense_delay(0); } }
  pub fn delay_us(us: u32) { unsafe { bindings::delay_us(us) } }
  pub fn delay_ms(ms: u32) { unsafe { bindings::delay_ms(ms) } }
  pub fn clock_ms() -> u64 { unsafe { bindings::get_clock_ms() } }

  pub fn is_mfg_mode() -> bool { unsafe { bindings::is_mfg_mode() } }
  pub fn set_mfg_mode_off() -> Result<(), ()> {
    match unsafe { bindings::set_mfg_mode_off() } {
      true => Ok(()),
      false => Err(()),
    }
  }

  pub fn flash_model() -> Option<&'static str> {
    let cstr = unsafe { cstr_core::CStr::from_ptr(bindings::flash_getModel() as *const cstr_core::c_char) };
    cstr.to_str().ok()
  }
  pub fn set_flash_model(model: &str) -> Result<(), ()> {
    match unsafe { bindings::flash_setModel(model.as_bytes().as_ptr(), model.len()) } {
      true => Ok(()),
      false => Err(()),
    }
  }

  pub fn flash_for_allocation<'a>(group: Allocation) -> impl core::iter::FusedIterator<Item = &'a [u8]> {
    let mut i = 0;
    return core::iter::from_fn(move || {
      let mut len: usize = 0;
      let data = unsafe { bindings::flash_write_helper(group, &mut len, i) };
      if data.is_null() { return None }
      i += 1;
      Some(unsafe { core::slice::from_raw_parts(data, len) })
    }).fuse()
  }

  pub fn button_down() -> bool { unsafe { bindings::keepkey_button_down() } }

  fn display_canvas_init() {
    CANVAS.call_once(|| {
      let height = unsafe { bindings::get_display_height() };
      let width = unsafe { bindings::get_display_width() };
      let len = height * width;
      let ptr = unsafe { bindings::get_static_canvas_buf(len) };
      assert!(!ptr.is_null());
      let buf = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
      let canvas = Canvas::new(height, width, buf);
      spin::Mutex::new(canvas)
    });
  }
  pub fn display_canvas() -> CanvasMutexGuard<'static> {
    Self::display_canvas_init();
    CANVAS.wait().try_lock().unwrap().into()
  }
  pub unsafe fn display_canvas_leak() -> &'static mut Canvas {
    Self::display_canvas_init();
    let mutex = CANVAS.wait();
    mutex.force_unlock();
    spin::MutexGuard::leak(mutex.lock())
  }
  pub fn display_refresh(canvas: &mut Canvas) { unsafe { bindings::display_refresh(&mut *canvas) } }

  pub fn set_led(act: LedAction) { unsafe { bindings::led_func(act) } }

  pub fn do_without_interrupts<F>(mut func: F) -> F::Output where F: FnMut() {
    unsafe { bindings::svc_disable_interrupts(); }
    let out = func();
    unsafe { bindings::svc_enable_interrupts(); }
    return out;
  }

  pub fn interrupt_lockout_count() -> u32 { unsafe { bindings::interrupt_lockout_count() } }

  pub fn usb() -> spin::MutexGuard<'static, UsbBusAllocator<UsbBus<Usb>>> {
    USB_BUS_ALLOCATOR.call_once(|| spin::Mutex::new(UsbBus::new(Usb(), unsafe { &mut EP_MEMORY })));
    USB_BUS_ALLOCATOR.wait().try_lock().unwrap()
  }
}
