use core::sync::atomic::{AtomicBool, Ordering};
use super::bindings;

static TAKEN: AtomicBool = AtomicBool::new(false);

pub struct KeepKeyRand {
  _0: (),
}

impl KeepKeyRand {
  pub fn take() -> Option<Self> {
    match TAKEN.swap(true, Ordering::Relaxed) {
      true => None,
      false => Some(unsafe { Self::steal() })
    }
  }

  pub unsafe fn steal() -> Self {
    Self { _0: () }
  }

  pub fn random_buffer(&self, data: &mut [u8]) {
    unsafe { bindings::random_buffer(data.as_mut_ptr(), data.len()) }
  }
}
