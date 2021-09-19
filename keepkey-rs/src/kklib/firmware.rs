use core::sync::atomic::{AtomicBool, Ordering};
use super::bindings;

static TAKEN: AtomicBool = AtomicBool::new(false);

pub struct KeepKeyFirmware {
  _0: (),
}

impl KeepKeyFirmware {
  pub fn take() -> Option<Self> {
    match TAKEN.swap(true, Ordering::Relaxed) {
      true => None,
      false => Some(unsafe { Self::steal() })
    }
  }

  pub unsafe fn steal() -> Self {
    Self { _0: () }
  }

  pub fn version(&self) -> (u8, u8, u8) {
    (unsafe { bindings::get_major_version() }, unsafe { bindings::get_minor_version() }, unsafe { bindings::get_patch_version() })
  }
  pub fn revision(&self) -> Option<&str> {
    let cstr = unsafe { cstr_core::CStr::from_ptr(bindings::get_scm_revision() as *const cstr_core::c_char) };
    cstr.to_str().ok()
  }

  pub fn storage_read(&self, data: &mut [u8]) -> Result<(), ()> {
    match unsafe { bindings::storage_read(data.as_mut_ptr(), data.len()) } {
      true => Ok(()),
      false => Err(()),
    }
  }
  pub fn storage_wipe(&mut self) { unsafe { bindings::storage_wipe() } }
  pub fn storage_write(&mut self, data: &[u8]) -> Result<(), ()> {
    match unsafe { bindings::storage_write(data.as_ptr(), data.len()) } {
      true => Ok(()),
      false => Err(()),
    }
  }
}
