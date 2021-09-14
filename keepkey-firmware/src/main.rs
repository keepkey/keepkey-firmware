#![no_main]
#![no_std]

extern crate panic_halt;

use stm32f2::stm32f215 as pac;

// mod usb;

// const DEVICE_LABEL: &str = "device_label";
// const SERIAL_UUID_STR: &str = "serial_uuid_str";

#[cortex_m_rt::entry]
fn main() -> ! {
    let dp = pac::Peripherals::take().unwrap();

    // adjust flash wait states
    dp.FLASH.acr.write(|w| unsafe { w.latency().bits(0b011) });

    // enable HSE and wait for it to be ready
    dp.RCC.cr.modify(|_, w| w.hseon().set_bit());
    while dp.RCC.cr.read().hserdy().bit_is_clear() {}

    // configure PLL
    dp.RCC.pllcfgr.modify(|_, w| unsafe {
        w.plln().bits(240);     // PLLN = 240
        w.pllm().bits(8);       // PLLM = 8
        w.pllp().bits(0b00);    // PLLP = 2
        w.pllq().bits(5);       // PLLQ = 5
        w.pllsrc().bit(true);   // HSE oscillator clock selected as PLL and PLLI2S clock entry
        w
    });

    // enable PLL and wait for it to be ready
    dp.RCC.cr.modify(|_, w| w.pllon().set_bit());
    while dp.RCC.cr.read().pllrdy().bit_is_clear() {}

    // set prescalers and clock source
    dp.RCC.cfgr.modify(|_, w| unsafe {
        w.rtcpre().bits(0b01000);   // HSE/8
        w.ppre2().bits(0b100);      // AHB clock divided by 2
        w.ppre1().bits(0b101);      // AHB clock divided by 4
        w.hpre().bits(0b0000);      // system clock not divided
        w.sw().bits(0b10);          // PLL selected as system clock
        w
    });

    dp.OTG_FS_GLOBAL.fs_gahbcfg.modify(|_, w| unsafe {
        w.gintmask().bit(true);     // Unmask the interrupt assertion to the application
        w.txfelvl().bit(true);      // the TXFE (in OTG_FS_DIEPINTx) interrupt indicates that the IN Endpoint TxFIFO is completely empty
        w
    });
    dp.OTG_FS_GLOBAL.fs_gusbcfg.modify(|_, w| unsafe {
        w.fdmod().bit(true);
        w.hnpcap().bit(false);
        w.srpcap().bit(false);
        w.trdt().bits(0x6);
        w.tocal().bits(16);
    });
    dp.OTG_FS_GLOBAL.fs_gccfg.modify(|_, w| unsafe { w.novbussens().bit(true) });

    // let usb_bus = stm32_usbd::UsbBus::new(usb::Peripheral {
    //     usb: dp.USB,
    //     pin_dm: stm32_hal2::gpio::Pin::new(stm32_hal2::gpio::Port::A, 11, stm32_hal2::gpio::PinMode::Output),
    //     pin_dp: stm32_hal2::gpio::Pin::new(stm32_hal2::gpio::Port::A, 12, stm32_hal2::gpio::PinMode::Input),
    // });
    // let mut usb_dev = usb_device::device::UsbDeviceBuilder::new(
    //     &usb_bus,
    //     usb_device::device::UsbVidPid(0x2b24, 0x0002),
    // )
    // .manufacturer("KeyHodlers, LLC")
    // .product(DEVICE_LABEL)
    // .device_release(0x0100)
    // .serial_number(SERIAL_UUID_STR)
    // .max_packet_size_0(64)
    // .composite_with_iads()
    // .build();

    // let mut wusb = usbd_webusb::WebUsb::new(
    //     &usb_bus,
    //     usbd_webusb::url_scheme::HTTPS,
    //     "beta.shapeshift.com",
    // );

    // initialization

    // var nOE_PIN = stm32f215::GPIOA.
    // static const Pin nOE_PIN = {GPIOA, GPIO8};
    // static const Pin nWE_PIN = {GPIOA, GPIO9};
    // static const Pin nDC_PIN = {GPIOB, GPIO1};

    // static const Pin nSEL_PIN = {GPIOA, GPIO10};
    // static const Pin nRESET_PIN = {GPIOB, GPIO5};

    // static const Pin BACKLIGHT_PWR_PIN = {GPIOB, GPIO0};

    // let mut backlight_pwr_pin = Pin::new(Port::B, 0, PinMode::Output);
    // backlight_pwr_pin.set_high();

    loop {
        // application logic
        // backlight_pwr_pin.toggle().unwrap();
        // cortex_m::asm::delay(72000000);
        // if !usb_dev.poll(&mut [&mut wusb]) {
        //     continue;
        // }
    }
}
