#[repr(u8)]
#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub enum Allocation {
  FlashInvalid,
  FlashBootstrap,
  FlashStorage1,
  FlashStorage2,
  FlashStorage3,
  FlashUnused0,
  FlashBootloader,
  FlashApp,
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub enum LedAction {
  ClrGreenLed,
  SetGreenLed,
  TglGreenLed,
  ClrRedLed,
  SetRedLed,
  TglRedLed,
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub enum ShutdownError {
  None = 0,
  RustPanic,
  StackSmashingProtection,
  ClockSecuritySystem,
  MemoryFault,
  NonMaskableInterrupt,
  ResetFailed,
  FaultInjectionDefense,
}
