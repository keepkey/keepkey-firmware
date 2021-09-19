use core::ops::{Deref, DerefMut, Drop};
use spin::MutexGuard;
use super::board::KeepKeyBoard;
use super::types::{Canvas, LedAction};

pub struct CanvasMutexGuard<'a> {
  _0: MutexGuard<'a, Canvas>
}

impl<'a> Deref for CanvasMutexGuard<'a> {
  type Target = Canvas;
  fn deref(&self) -> &Self::Target { &self._0 }
}

impl<'a> DerefMut for CanvasMutexGuard<'a> {
  fn deref_mut(&mut self) -> &mut Self::Target { &mut self._0 }
}

impl<'a> Drop for CanvasMutexGuard<'a> {
  fn drop(&mut self) {
    KeepKeyBoard::display_refresh(self);
    KeepKeyBoard::set_led(LedAction::TglRedLed);
  }
}

impl<'a> From<MutexGuard<'a, Canvas>> for CanvasMutexGuard<'a> {
  fn from(guard: MutexGuard<'a, Canvas>) -> Self {
    CanvasMutexGuard { _0: guard }
  }
}
