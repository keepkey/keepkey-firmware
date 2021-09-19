#![allow(dead_code)]
use super::types::{Allocation, Canvas, ShutdownError, LedAction};

#[link(name = "kkboard")]
extern "C" {
  pub fn shutdown_with_error(error: ShutdownError) -> !;
  pub fn board_reset() -> !;

  pub fn fi_defense_delay(value: u32) -> u32;
  pub fn delay_us(us: u32);
  pub fn delay_ms(ms: u32);
  pub fn get_clock_ms() -> u64;

  pub fn is_mfg_mode() -> bool;
  pub fn set_mfg_mode_off() -> bool;

  pub fn flash_getModel() -> *const u8;
  pub fn flash_setModel(buf: *const u8, len: usize) -> bool;

  pub fn flash_write_helper(group: Allocation, pLen: *mut usize, skip: usize) -> *const u8;

  pub fn keepkey_button_down() -> bool;

  pub fn get_display_height() -> usize;
  pub fn get_display_width() -> usize;
  pub fn get_static_canvas_buf(len: usize) -> *mut u8;
  pub fn display_refresh(canvas: *mut Canvas);

  pub fn led_func(act: LedAction);

  pub fn usb_tx(buf: *const u8, len: u32) -> bool;
  pub fn usb_debug_tx(buf: *const u8, len: u32) -> bool;
  pub fn usbReconnect();

  pub fn desig_get_unique_id2(out: *mut u32);

  pub fn svc_disable_interrupts();
  pub fn svc_enable_interrupts();

  pub fn interrupt_lockout_count() -> u32;
}

#[link(name = "kkfirmware")]
extern "C" {
  pub fn get_major_version() -> u8;
  pub fn get_minor_version() -> u8;
  pub fn get_patch_version() -> u8;
  pub fn get_scm_revision() -> *const u8;

  pub fn storage_read(buf: *mut u8, len: usize) -> bool;
  pub fn storage_wipe();
  pub fn storage_write(buf: *const u8, len: usize) -> bool;
}

#[link(name = "kkrand")]
extern "C" {
  pub fn random_buffer(buf: *mut u8, len: usize);
}
