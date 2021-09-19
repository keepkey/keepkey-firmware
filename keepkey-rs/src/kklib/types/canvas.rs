#![allow(dead_code)]

use core::convert::{Infallible, TryInto};
use embedded_graphics::pixelcolor::Gray8;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;

#[repr(C)]
pub struct Canvas {
  _height: u16,
  _width: u16,
  _constant_power: bool,
  _buffer: usize,
  _buffer_dirty: bool,
  _brightness: u8,
  _brightness_dirty: bool,
  _powered: bool,
  _powered_dirty: bool,
}

impl Canvas {
  pub fn new(height: usize, width: usize, buffer: &'static mut [u8]) -> Self {
    assert!(buffer.len() >= height as usize * width as usize);
    let mut out = Self {
      _height: height.try_into().unwrap(),
      _width: width.try_into().unwrap(),
      _constant_power: false,
      _buffer: unsafe { core::mem::transmute(buffer.as_mut_ptr()) },
      _buffer_dirty: false,
      _brightness: 100,
      _brightness_dirty: true,
      _powered: true,
      _powered_dirty: true,
    };
    let _ = out.clear(GrayColor::BLACK);
    out
  }
  pub unsafe fn buffer_mut_unsafe(&self) -> &mut [u8] {
    let len = self._height as usize * self._width as usize;
    core::slice::from_raw_parts_mut(core::mem::transmute(self._buffer), len)
  }
  pub fn buffer_mut(&mut self) -> &mut [u8] {
    unsafe { self.buffer_mut_unsafe() }
  }
  pub fn set_brightness(&mut self, brightness: u8) {
    if self._brightness != brightness {
      self._brightness = brightness;
      self._brightness_dirty = true;
    }
  }
  pub fn set_powered(&mut self, powered: bool) {
    if self._powered != powered {
      self._powered = powered;
      self._powered_dirty = true;
    }
  }
  pub fn set_constant_power(&mut self, constant_power: bool) {
    if self._constant_power != constant_power {
      self._constant_power = constant_power;
      self._buffer_dirty = true;
    }
  }
  fn constant_power_offset(&self) -> Point {
    match self._constant_power {
      false => Point::zero(),
      true => Point::new((self._width / 2).into(), 0),
    }
  }
}

impl OriginDimensions for Canvas {
  fn size(&self) -> Size {
    match self._constant_power {
      false => Size::new(self._width as u32, self._height as u32),
      true => Size::new((self._width as u32) / 2, self._height as u32),
    }
  }
}

impl DrawTarget for Canvas {
  type Color = Gray8;
  type Error = Infallible;

  fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
  where
    I: IntoIterator<Item = Pixel<Self::Color>>,
  {
    let Rectangle { top_left, size } = self.bounding_box();
    let bottom_right = top_left + size;
    let constant_power_offset = self.constant_power_offset();

    let buf = self.buffer_mut();
    for Pixel(coord, color) in pixels.into_iter() {
      if let Ok((x, y)) = TryInto::<(i32, i32)>::try_into(coord + constant_power_offset) {
        if (top_left.x..bottom_right.x).contains(&x) && (top_left.y..bottom_right.y).contains(&y) {
          if let Some(i) = TryInto::<usize>::try_into((y * (size.width as i32)) + x).ok() {
            buf[i] = color.luma();
          }
        }
      }
    }

    self._buffer_dirty = true;
    Ok(())
  }

  // fn fill_contiguous<I>(&mut self, area: &Rectangle, colors: I) -> Result<(), Self::Error>
  // where
  //   I: IntoIterator<Item = Self::Color>,
  // {
  //   let shifted_area = Rectangle::new(area.top_left + self.constant_power_offset(), area.size);
  //   let drawable_area = self.bounding_box().intersection(&shifted_area);

  //   let wraparound = (self.bounding_box().size.width - drawable_area.size.width) as i32;
  //   let mut off =
  //     (drawable_area.top_left.y * drawable_area.size.width as i32) + drawable_area.top_left.x;
  //   let mut i = 0;

  //   let buf = self.buffer_mut();
  //   for color in colors.into_iter() {
  //     i += 1;
  //     off += 1;
  //     if i == drawable_area.size.width as i32 {
  //       i = 0;
  //       off += wraparound;
  //     }
  //     buf[off as usize] = color.luma();
  //   }

  //   self._buffer_dirty = true;
  //   Ok(())
  // }

  // fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
  //   let shifted_area = Rectangle::new(area.top_left + self.constant_power_offset(), area.size);
  //   let drawable_area = self.bounding_box().intersection(&shifted_area);
  //   let color_raw = color.luma();
    
  //   let mut off = ((drawable_area.top_left.y * drawable_area.size.width as i32)
  //     + drawable_area.top_left.x) as usize;

  //   let buf = self.buffer_mut();
  //   for _ in 0..drawable_area.size.height {
  //     safemem::write_bytes(
  //       &mut buf[off..][..drawable_area.size.width as usize],
  //       color_raw,
  //     );
  //     off += drawable_area.size.width as usize;
  //   }

  //   self._buffer_dirty = true;
  //   Ok(())
  // }

  fn clear(&mut self, color: Self::Color) -> Result<(), Self::Error> {
    safemem::write_bytes(self.buffer_mut(), color.luma());

    self._buffer_dirty = true;
    Ok(())
  }
}
