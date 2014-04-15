/*----------------------------------------------------------------------------
 * Name:    STM32_Init.c
 * Purpose: STM32 peripherals initialisation
 * Version: V1.27
 * Note(s):
 *----------------------------------------------------------------------------
 * This file is part of the uVision/ARM development tools.
 * This software may only be used under the terms of a valid, current,
 * end user licence from KEIL for a compatible version of KEIL software
 * development tools. Nothing else gives you the right to use this software.
 *
 * This software is supplied "AS IS" without warranties of any kind.
 *
 * Copyright (c) 2005-2009 Keil Software. All rights reserved.
 *----------------------------------------------------------------------------
 * History:
 *          V1.27 error correction for Nested Vectored Interrupt Controller Section
 *          V1.26 added register GPIOF, GPIOG
 *                added GPIOF, GPIOG to External interrupt/event Configuration
 *          V1.25 error correction for USART section
 *          V1.24 changed function definition to 'static inline'
 *          V1.23 error correction for RTC configuration (LSI selected)
 *          V1.22 added Nested Vectored Interrupt Controller Section
 *          V1.21 error correction for timer settings
 *          V1.20 added Alternate Function remap Configuration Section
 *                error correction for timer settings
 *          V1.10 added more Sections 
 *          V1.00 Initial Version
 *----------------------------------------------------------------------------*/

#include <stm32f10x_lib.h>                        // STM32F10x Library Definitions
#include "STM32_Reg.h"                            // missing bit definitions

//-------- <<< Use Configuration Wizard in Context Menu >>> -----------------
//


//=========================================================================== Clock Configuration
// <e0> Clock Configuration
//   <h> Clock Control Register Configuration (RCC_CR)
//     <e1.24> PLLON: PLL enable         
//       <i> Default: PLL Disabled
//       <o2.18..21> PLLMUL: PLL Multiplication Factor
//         <i> Default: PLLSRC * 2
//                       <0=> PLLSRC * 2
//                       <1=> PLLSRC * 3
//                       <2=> PLLSRC * 4
//                       <3=> PLLSRC * 5
//                       <4=> PLLSRC * 6
//                       <5=> PLLSRC * 7
//                       <6=> PLLSRC * 8
//                       <7=> PLLSRC * 9
//                       <8=> PLLSRC * 10
//                       <9=> PLLSRC * 11
//                       <10=> PLLSRC * 12
//                       <11=> PLLSRC * 13
//                       <12=> PLLSRC * 14
//                       <13=> PLLSRC * 15
//                       <14=> PLLSRC * 16
//       <o2.17> PLLXTPRE: HSE divider for PLL entry
//         <i> Default: HSE
//                       <0=> HSE
//                       <1=> HSE / 2
//       <o2.16> PLLSRC: PLL entry clock source         
//         <i> Default: HSI/2
//                       <0=> HSI / 2
//                       <1=> HSE (PLLXTPRE output)
//     </e>
//     <o1.19> CSSON: Clock Security System enable
//       <i> Default: Clock detector OFF
//     <o1.18> HSEBYP: External High Speed clock Bypass
//       <i> Default: HSE oscillator not bypassed
//     <o1.16> HSEON: External High Speed clock enable 
//       <i> Default: HSE oscillator OFF
//     <o1.3..7> HSITRIM: Internal High Speed clock trimming  <0-31>
//       <i> Default: 0
//     <o1.0> HSION: Internal High Speed clock enable
//       <i> Default: internal 8MHz RC oscillator OFF
//   </h>
//   <h> Clock Configuration Register Configuration (RCC_CFGR)
//     <o2.24..26> MCO: Microcontroller Clock Output   
//       <i> Default: MCO = noClock
//                     <0=> MCO = noClock
//                     <4=> MCO = SYSCLK
//                     <5=> MCO = HSI
//                     <6=> MCO = HSE
//                     <7=> MCO = PLLCLK / 2
//     <o2.22> USBPRE: USB prescaler
//       <i> Default: USBCLK = PLLCLK / 1.5
//                     <0=> USBCLK = PLLCLK / 1.5
//                     <1=> USBCLK = PLLCLK
//     <o2.14..15> ADCPRE: ADC prescaler
//       <i> Default: ADCCLK=PCLK2 / 2
//                     <0=> ADCCLK = PCLK2 / 2
//                     <1=> ADCCLK = PCLK2 / 4
//                     <2=> ADCCLK = PCLK2 / 6
//                     <3=> ADCCLK = PCLK2 / 8
//     <o2.11..13> PPRE2: APB High speed prescaler (APB2)
//       <i> Default: PCLK2 = HCLK
//                     <0=> PCLK2 = HCLK
//                     <4=> PCLK2 = HCLK / 2 
//                     <5=> PCLK2 = HCLK / 4 
//                     <6=> PCLK2 = HCLK / 8 
//                     <7=> PCLK2 = HCLK / 16 
//     <o2.8..10> PPRE1: APB Low speed prescaler (APB1) 
//       <i> Default: PCLK1 = HCLK
//                     <0=> PCLK1 = HCLK
//                     <4=> PCLK1 = HCLK / 2 
//                     <5=> PCLK1 = HCLK / 4 
//                     <6=> PCLK1 = HCLK / 8 
//                     <7=> PCLK1 = HCLK / 16 
//     <o2.4..7> HPRE: AHB prescaler 
//       <i> Default: HCLK = SYSCLK
//                     <0=> HCLK = SYSCLK
//                     <8=> HCLK = SYSCLK / 2
//                     <9=> HCLK = SYSCLK / 4
//                     <10=> HCLK = SYSCLK / 8
//                     <11=> HCLK = SYSCLK / 16
//                     <12=> HCLK = SYSCLK / 64
//                     <13=> HCLK = SYSCLK / 128
//                     <14=> HCLK = SYSCLK / 256
//                     <15=> HCLK = SYSCLK / 512
//     <o2.0..1> SW: System Clock Switch
//       <i> Default: SYSCLK = HSE
//                     <0=> SYSCLK = HSI
//                     <1=> SYSCLK = HSE
//                     <2=> SYSCLK = PLLCLK
//   </h>
//   <o3>HSE: External High Speed Clock [Hz] <4000000-16000000>
//   <i> clock value for the used External High Speed Clock (4MHz <= HSE <= 16MHz).
//   <i> Default: 8000000  (8MHz)
// </e> End of Clock Configuration
#define __CLOCK_SETUP              1
#define __RCC_CR_VAL               0x01010082
#define __RCC_CFGR_VAL             0x001D8402
#define __HSE                      8000000


//=========================================================================== Nested Vectored Interrupt Controller
// <e0> Nested Vectored Interrupt Controller (NVIC)
//   <e1.0> Vector Table Offset Register 
//     <o2.29> TBLBASE: Vector Table Base         
//       <i> Default: FLASH
//              <0=> FLASH
//              <1=> RAM
//     <o2.7..28> TBLOFF: Vector Table Offset <0x0-0x1FFFFFC0:0x80><#/0x80>
//       <i> Default: 0x00000000
//   </e>
// </e> End of Clock Configuration
#define __NVIC_SETUP              0
#define __NVIC_USED               0x00000000
#define __NVIC_VTOR_VAL           0x00000000


//=========================================================================== Independent Watchdog Configuration
// <e0> Independent Watchdog Configuration
//   <o1> IWDG period [us] <125-32000000:125>
//   <i> Set the timer period for Independent Watchdog.
//   <i> Default: 1000000  (1s)
// </e>
#define __IWDG_SETUP              0
#define __IWDG_PERIOD             0x001E8480


//=========================================================================== System Timer Configuration
// <e0> System Timer Configuration
//   <o1.2> System Timer clock source selection
//   <i> Default: SYSTICKCLK = HCLK/8
//                     <0=> SYSTICKCLK = HCLK/8
//                     <1=> SYSTICKCLK = HCLK
//   <o2> SYSTICK period [ms] <1-1000:10>
//   <i> Set the timer period for System Timer.
//   <i> Default: 1  (1ms)
//   <o1.1> System Timer interrupt enabled
// </e>
#define __SYSTICK_SETUP           0
#define __SYSTICK_CTRL_VAL        0x00000006
#define __SYSTICK_PERIOD          0x000000C8


//=========================================================================== Real Time Clock Configuration
// <e0> Real Time Clock Configuration
//   <o1.8..9> RTC clock source selection
//   <i> Default: No Clock
//                     <0=> No Clock
//                     <1=> RTCCLK = LSE (32,768kHz)
//                     <2=> RTCCLK = LSI (32 kHz)
//                     <3=> RTCCLK = HSE/128
//   <o2> RTC period [ms] <10-1000:10>
//   <i> Set the timer period for Real Time Clock.
//   <i> Default: 1000  (1s)
//   <h> RTC Time Value
//     <o3> Hour <0-23>
//     <o4> Minute <0-59>
//     <o5> Second <0-59>
//   </h>
//   <h> RTC Alarm Value
//     <o6> Hour <0-23>
//     <o7> Minute <0-59>
//     <o8> Second <0-59>
//   </h>
//   <e9> RTC interrupts
//     <o10.0> RTC_CRH.SECIE: Second interrupt enabled
//     <o10.1> RTC_CRH.ALRIE: Alarm interrupt enabled
//     <o10.2> RTC_CRH.OWIE: Overflow interrupt enabled
//   </e>
// </e>
#define __RTC_SETUP               0
#define __RTC_CLKSRC_VAL          0x00000100
#define __RTC_PERIOD              0x000003E8
#define __RTC_TIME_H              0x00
#define __RTC_TIME_M              0x00
#define __RTC_TIME_S              0x00
#define __RTC_ALARM_H             0x00
#define __RTC_ALARM_M             0x01
#define __RTC_ALARM_S             0x00
#define __RTC_INTERRUPTS          0x00000001
#define __RTC_CRH                 0x00000001


//=========================================================================== Timer Configuration
// <e0> Timer Configuration
//--------------------------------------------------------------------------- Timer 1 enabled
//   <e1.0> TIM1 : Timer 1 enabled
//     <o4> TIM1 period [us] <1-72000000:10>
//       <i> Set the timer period for Timer 1.
//       <i> Default: 1000  (1ms)
//       <i> Ignored if detailed settings is selected
//     <o7> TIM1 repetition counter <0-255>
//       <i> Set the repetition counter for Timer 1.
//       <i> Default: 0
//       <i> Ignored if detailed settings is selected
//     <e2.0> TIM1 detailed settings
//--------------------------------------------------------------------------- Timer 1 detailed settings
//       <o5> TIM1.PSC: Timer1 Prescaler <0-65535>
//         <i> Set the prescaler for Timer 1.
//       <o6> TIM1.ARR: Timer1 Auto-reload <0-65535>
//         <i> Set the Auto-reload for Timer 1.
//       <o7> TIM1.RCR: Timer1 Repetition Counter <0-255>
//         <i> Set the Repetition Counter for Timer 1.
//
//       <h> Timer 1 Control Register 1 Configuration (TIM1_CR1)
//         <o8.8..9> TIM1_CR1.CKD: Clock division   
//           <i> Default: tDTS = tCK_INT
//           <i> devision ratio between timer clock and dead time
//                     <0=> tDTS = tCK_INT
//                     <1=> tDTS = 2*tCK_INT
//                     <2=> tDTS = 4*tCK_INT
//         <o8.7> TIM1_CR1.ARPE: Auto-reload preload enable
//           <i> Default: Auto-reload preload disenabled
//         <o8.5..6> TIM1_CR1.CMS: Center aligned mode selection   
//           <i> Default: Edge-aligned
//                     <0=> Edge-aligned
//                     <1=> Center-aligned mode1
//                     <2=> Center-aligned mode2
//                     <3=> Center-aligned mode3
//         <o8.4> TIM1_CR1.DIR: Direction
//           <i> Default: DIR = Counter used as up-counter
//           <i> read only if timer is configured as Center-aligned or Encoder mode   
//                     <0=> Counter used as up-counter
//                     <1=> Counter used as down-counter
//         <o8.3> TIM1_CR1.OPM: One pulse mode enable
//           <i> Default: One pulse mode disabled
//         <o8.2> TIM1_CR1.URS: Update request source   
//           <i> Default: URS = Counter over-/underflow, UG bit, Slave mode controller
//                     <0=> Counter over-/underflow, UG bit, Slave mode controller
//                     <1=> Counter over-/underflow
//         <o8.1> TIM1_CR1.UDIS: Update disable
//           <i> Default: Update enabled
//       </h>
//
//       <h> Timer 1 Control Register 2 Configuration (TIM1_CR2)
//         <o9.14> TIM1_CR2.OIS4: Output Idle state4 (OC4 output)   <0-1>
//         <o9.13> TIM1_CR2.OIS3N: Output Idle state3 (OC3N output) <0-1>
//         <o9.12> TIM1_CR2.OIS3: Output Idle state3 (OC3 output)   <0-1>
//         <o9.11> TIM1_CR2.OIS2N: Output Idle state2 (OC2N output) <0-1> 
//         <o9.10> TIM1_CR2.OIS2: Output Idle state2 (OC2 output)   <0-1>
//         <o9.9> TIM1_CR2.OIS1N: Output Idle state1 (OC1N output)
//           <i> Default: OC1 = 0
//                     <0=> OC1N=0 when MOE=0
//                     <1=> OC1N=1 when MOE=0
//         <o9.8> TIM1_CR2.OI1S: Output Idle state1 (OC1 output)  
//           <i> Default: OC1=0
//                     <0=> OC1=0 when MOE=0
//                     <1=> OC1=1 when MOE=0
//         <o9.7> TIM1_CR2.TI1S: TI1 Selection  
//           <i> Default: TIM1CH1 connected to TI1 input
//                     <0=> TIM1CH1 connected to TI1 input
//                     <1=> TIM1CH1,CH2,CH3 connected to TI1 input
//         <o9.4..6> TIM1_CR2.MMS: Master Mode Selection  
//           <i> Default: Reset
//           <i> Select information to be sent in master mode to slave timers for synchronisation
//                     <0=> Reset
//                     <1=> Enable
//                     <2=> Update
//                     <3=> Compare Pulse
//                     <4=> Compare OC1REF iused as TRGO
//                     <5=> Compare OC2REF iused as TRGO
//                     <6=> Compare OC3REF iused as TRGO
//                     <7=> Compare OC4REF iused as TRGO
//         <o9.2> TIM1_CR2.CCUS: Capture/Compare Control Update Selection  
//           <i> Default: setting COM bit
//                     <0=> setting COM bit
//                     <1=> setting COM bit or rising edge TRGI
//         <o9.0> TIM1_CR2.CCPC: Capture/Compare Preloaded Control   
//           <i> Default: CCxE,CCxNE,OCxM not preloaded
//                     <0=> CCxE,CCxNE,OCxM not preloaded
//                     <1=> CCxE,CCxNE,OCxM preloaded
//       </h>
//
//       <h> Timer 1 Slave mode control register Configuration (TIM1_SMC)
//         <o10.15> TIM1_SMCR.ETP: External trigger polarity
//           <i> Default: ETR is non-inverted
//                     <0=> ETR is non-inverted
//                     <1=> ETR is inverted
//         <o10.14> TIM1_SMCR.ECE: External clock mode 2 enabled
//         <o10.12..13> TIM1_SMCR.ETPS: External trigger prescaler  
//           <i> Default: Prescaler OFF
//                     <0=> Prescaler OFF
//                     <1=> fETPR/2
//                     <2=> fETPR/4
//                     <3=> fETPR/8
//         <o10.8..11> TIM1_SMCR.ETF: External trigger filter  
//           <i> Default: No filter
//                     <0=>  No filter
//                     <1=>  fSampling=fCK_INT, N=2
//                     <2=>  fSampling=fCK_INT, N=4
//                     <3=>  fSampling=fCK_INT, N=8
//                     <4=>  fSampling=fDTS/2, N=6
//                     <5=>  fSampling=fDTS/2, N=8
//                     <6=>  fSampling=fDTS/4, N=6
//                     <7=>  fSampling=fDTS/4, N=8
//                     <8=>  fSampling=fDTS/8, N=6
//                     <9=>  fSampling=fDTS/8, N=8
//                     <10=> fSampling=fDTS/16, N=5
//                     <11=> fSampling=fDTS/16, N=6
//                     <12=> fSampling=fDTS/16, N=8
//                     <13=> fSampling=fDTS/32, N=5
//                     <14=> fSampling=fDTS/32, N=6
//                     <15=> fSampling=fDTS/32, N=8
//         <o10.7> TIM1_SMCR.MSM: Delay trigger input  
//         <o10.4..6> TIM1_SMCR.TS: Trigger Selection  
//           <i> Default: Reserved
//                     <0=> Reserved
//                     <1=> TIM2 (ITR1)
//                     <2=> TIM3 (ITR2)
//                     <3=> TIM4 (ITR3)
//                     <4=> TI1 Edge Detector (TI1F_ED)
//                     <5=> Filtered Timer Input 1 (TI1FP1)
//                     <6=> Filtered Timer Input 2 (TI1FP2)
//                     <7=> External Trigger Input (ETRF)
//         <o10.0..2> TIM1_SMCR.SMS: Slave mode selection   
//           <i> Default: Slave mode disabled
//                     <0=> Slave mode disabled
//                     <1=> Encoder mode 1
//                     <2=> Encoder mode 2
//                     <3=> Encoder mode 3
//                     <4=> Reset mode
//                     <5=> Gated mode
//                     <6=> Trigger mode
//                     <7=> External clock mode 1
//       </h>
//
//--------------------------------------------------------------------------- Timer 1 channel 1
//       <h> Channel 1 Configuration
//         <h> Cannel configured as output
//           <o11.7> TIM1_CCMR1.OC1CE: Output Compare 1 Clear enabled  
//           <o11.4..6> TIM1_CCMR1.OC1M: Output Compare 1 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 1 to active level on match
//                       <2=>  Set channel 1 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o11.3> TIM1_CCMR1.OC1PE: Output Compare 1 Preload enabled  
//           <o11.2> TIM1_CCMR1.OC1FE: Output Compare 1 Fast enabled  
//           <o11.0..1> TIM1_CCMR1.CC1S: Capture/compare 1 selection   
//             <i> Default: CC1 configured as output
//                       <0=> CC1 configured as output
//           <o13.3> TIM1_CCER.CC1NP: Capture/compare 1 Complementary output Polarity set  
//             <i> Default: OC1N active high
//                       <0=> OC1N active high
//                       <1=> OC1N active low
//           <o13.2> TIM1_CCER.CC1NE: Capture/compare 1 Complementary output enabled
//             <i> Default: OC1N not active
//                       <0=> OC1N not active
//                       <1=> OC1N is output on corresponding pin
//           <o13.1> TIM1_CCER.CC1P: Capture/compare 1 output Polarity set  
//             <i> Default: OC1 active high
//                       <0=> OC1 active high
//                       <1=> OC1 active low
//           <o13.0>  TIM1_CCER.CC1E: Capture/compare 1 output enabled   
//             <i> Default: OC1 not active
//                       <0=> OC1 not active
//                       <1=> OC1 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o11.4..7> TIM1_CCMR1.IC1F: Input Capture 1 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o11.2..3> TIM1_CCMR1.IC1PSC: Input Capture 1 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o11.0..1> TIM1_CCMR1.CC1S: Capture/compare 1 selection   
//             <i> Default: CC1 configured as output
//                       <0=> CC1 configured as output
//                       <1=> CC1 configured as input, IC1 mapped on TI1
//                       <2=> CC1 configured as input, IC1 mapped on TI2
//                       <3=> CC1 configured as input, IC1 mapped on TRGI
//           <o13.1>  TIM1_CCER.CC1P: Capture/compare 1 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o13.0>  TIM1_CCER.CC1E: Capture/compare 1 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o14> TIM1_CCR1: Capture/compare register 1 <0-65535>
//         <i> Set the Compare register value for compare register 1.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 1 channel 2
//       <h> Channel 2 Configuration
//         <h> Cannel configured as output
//           <o11.15> TIM1_CCMR1.OC2CE: Output Compare 2 Clear enabled  
//           <o11.12..14> TIM1_CCMR1.OC2M: Output Compare 2 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 2 to active level on match
//                       <2=>  Set channel 2 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o11.11> TIM1_CCMR1.OC2PE: Output Compare 2 Preload enabled  
//           <o11.10> TIM1_CCMR1.OC2FE: Output Compare 2 Fast enabled  
//           <o11.8..9> TIM1_CCMR1.CC2S: Capture/compare 2 selection   
//             <i> Default: CC2 configured as output
//                       <0=> CC2 configured as output
//           <o13.7> TIM1_CCER.CC2NP: Capture/compare 2 Complementary output Polarity set  
//             <i> Default: OC2N active high
//                       <0=> OC2N active high
//                       <1=> OC2N active low
//           <o13.6> TIM1_CCER.CC2NE: Capture/compare 2 Complementary output enabled
//             <i> Default: OC2N not active
//                       <0=> OC2N not active
//                       <1=> OC2N is output on corresponding pin
//           <o13.5>  TIM1_CCER.CC2P: Capture/compare 2 output Polarity set  
//             <i> Default: OC2 active high
//                       <0=> OC2 active high
//                       <1=> OC2 active low
//           <o13.4>  TIM1_CCER.CC2E: Capture/compare 2 output enabled   
//             <i> Default: OC2 not active
//                       <0=> OC2 not active
//                       <1=> OC2 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o11.12..15> TIM1_CCMR1.IC2F: Input Capture 2 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o11.10..11> TIM1_CCMR1.IC2PSC: Input Capture 2 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o11.8..9> TIM1_CCMR1.CC2S: Capture/compare 2 selection   
//             <i> Default: CC2 configured as output
//                       <0=> CC2 configured as output
//                       <1=> CC2 configured as input, IC2 mapped on TI2
//                       <2=> CC2 configured as input, IC2 mapped on TI1
//                       <3=> CC2 configured as input, IC2 mapped on TRGI
//           <o13.5>  TIM1_CCER.CC2P: Capture/compare 2 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o13.4>  TIM1_CCER.CC2E: Capture/compare 2 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o15> TIM1_CCR2: Capture/compare register 2 <0-65535>
//         <i> Set the Compare register value for compare register 2.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 1 channel 3
//       <h> Channel 3 Configuration
//         <h> Cannel configured as output
//           <o12.7> TIM1_CCMR2.OC3CE: Output Compare 3 Clear enabled  
//           <o12.4..6> TIM1_CCMR2.OC3M: Output Compare 3 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 3 to active level on match
//                       <2=>  Set channel 3 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o12.3> TIM1_CCMR2.OC3PE: Output Compare 3 Preload enabled  
//           <o12.2> TIM1_CCMR2.OC3FE: Output Compare 3 Fast enabled  
//           <o12.0..1> TIM1_CCMR2.CC3S: Capture/compare 3 selection   
//             <i> Default: CC3 configured as output
//                       <0=> CC3 configured as output
//           <o13.11> TIM1_CCER.CC3NP: Capture/compare 3 Complementary output Polarity set  
//             <i> Default: OC3N active high
//                       <0=> OC3N active high
//                       <1=> OC3N active low
//           <o13.10> TIM1_CCER.CC3NE: Capture/compare 3 Complementary output enabled
//             <i> Default: OC3N not active
//                       <0=> OC3N not active
//                       <1=> OC3N is output on corresponding pin
//           <o13.9>  TIM1_CCER.CC3P: Capture/compare 3 output Polarity set  
//             <i> Default: OC3 active high
//                       <0=> OC3 active high
//                       <1=> OC3 active low
//           <o13.8>  TIM1_CCER.CC3E: Capture/compare 3 output enabled   
//             <i> Default: OC3 not active
//                       <0=> OC3 not active
//                       <1=> OC3 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o12.4..7> TIM1_CCMR2.IC3F: Input Capture 3 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o12.2..3> TIM1_CCMR2.IC3PSC: Input Capture 3 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o12.0..1> TIM1_CCMR2.CC3S: Capture/compare 3 selection   
//             <i> Default: CC3 configured as output
//                       <0=> CC3 configured as output
//                       <1=> CC3 configured as input, IC3 mapped on TI3
//                       <2=> CC3 configured as input, IC3 mapped on TI4
//                       <3=> CC3 configured as input, IC3 mapped on TRGI
//           <o13.9>  TIM1_CCER.CC3P: Capture/compare 3 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o13.8>  TIM1_CCER.CC3E: Capture/compare 3 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o16> TIM1_CCR3: Capture/compare register 3 <0-65535>
//         <i> Set the Compare register value for compare register 3.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 1 channel 4
//       <h> Channel 4 Configuration
//         <h> Cannel configured as output
//           <o12.15> TIM1_CCMR2.OC4CE: Output Compare 4 Clear enabled  
//           <o12.12..14> TIM1_CCMR2.OC4M: Output Compare 4 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 4 to active level on match
//                       <2=>  Set channel 4 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o12.11> TIM1_CCMR2.OC4PE: Output Compare 4 Preload enabled  
//           <o12.10> TIM1_CCMR2.OC4FE: Output Compare 4 Fast enabled  
//           <o12.8..9> TIM1_CCMR2.CC4S: Capture/compare 4 selection   
//             <i> Default: CC4 configured as output
//                       <0=> CC4 configured as output
//           <o13.13>  TIM1_CCER.CC4P: Capture/compare 4 output Polarity set  
//             <i> Default: OC4 active high
//                       <0=> OC4 active high
//                       <1=> OC4 active low
//           <o13.12>  TIM1_CCER.CC4E: Capture/compare 4 output enabled   
//             <i> Default: OC4 not active
//                       <0=> OC4 not active
//                       <1=> OC4 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o12.12..15> TIM1_CCMR2.IC4F: Input Capture 4 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o12.10..11> TIM1_CCMR2.IC4PSC: Input Capture 4 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o12.8..9> TIM1_CCMR2.CC4S: Capture/compare 4 selection   
//             <i> Default: CC4 configured as output
//                       <0=> CC4 configured as output
//                       <1=> CC4 configured as input, IC4 mapped on TI4
//                       <2=> CC4 configured as input, IC4 mapped on TI3
//                       <3=> CC4 configured as input, IC4 mapped on TRGI
//           <o13.13>  TIM1_CCER.CC4P: Capture/compare 4 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o13.12>  TIM1_CCER.CC4E: Capture/compare 4 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o17> TIM1_CCR4: Capture/compare register 4 <0-65535>
//         <i> Set the Compare register value for compare register 4.
//         <i> Default: 0
//     </h>
//
//       <h> Timer1 Break and dead-time register Configuration (TIM1_BDTR)
//         <o18.15> TIM1_BDTR.MOE: Main Output enabled
//         <o18.14> TIM1_BDTR.AOE: Automatic Output enabled
//         <o18.13> TIM1_BDTR.BKP: Break Polarity active high
//         <o18.12> TIM1_BDTR.BKE: Break Inputs enabled
//         <o18.11> TIM1_BDTR.OSSR: Off-State Selection for Run mode
//           <i> Default: OC/OCN output signal=0
//                     <0=> OC/OCN output signal=0
//                     <1=> OC/OCN output signal=1
//         <o18.10> TIM1_BDTR.OSSI: Off-State Selection for Idle mode
//           <i> Default: OC/OCN output signal=0
//                     <0=> OC/OCN output signal=0
//                     <1=> OC/OCN output signal=1
//         <o18.8..9> TIM1_BDTR.LOCK: Lock Level <0-3>
//           <i> Default: 0 (LOCK OFF)
//         <o18.0..7> TIM1_BDTR.DTG: Dead-Time Generator set-up <0x00-0xFF>   
//       </h>
//
//     </e>
//     <e3.0> TIM1 interrupts
//       <o19.14> TIM1_DIER.TDE: Trigger DMA request enabled
//       <o19.12> TIM1_DIER.CC4DE: Capture/Compare 4 DMA request enabled
//       <o19.11> TIM1_DIER.CC3DE: Capture/Compare 3 DMA request enabled
//       <o19.10> TIM1_DIER.CC2DE: Capture/Compare 2 DMA request enabled
//       <o19.9>  TIM1_DIER.CC1DE: Capture/Compare 1 DMA request enabled
//       <o19.8>  TIM1_DIER.UDE: Update DMA request enabled
//       <o19.7>  TIM1_DIER.BIE: Break interrupt enabled
//       <o19.6>  TIM1_DIER.TIE: Trigger interrupt enabled
//       <o19.5>  TIM1_DIER.COMIE: COM interrupt enabled
//       <o19.4>  TIM1_DIER.CC4IE: Capture/Compare 4 interrupt enabled
//       <o19.3>  TIM1_DIER.CC3IE: Capture/Compare 3 interrupt enabled
//       <o19.2>  TIM1_DIER.CC2IE: Capture/Compare 2 interrupt enabled
//       <o19.1>  TIM1_DIER.CC1IE: Capture/Compare 1 interrupt enabled
//       <o19.0>  TIM1_DIER.UIE: Update interrupt enabled
//     </e>
//   </e>
//--------------------------------------------------------------------------- Timer 2 enabled
//   <e1.1> TIM2 : Timer 2 enabled
//     <o20> TIM2 period [us] <1-72000000:10>
//       <i> Set the timer period for Timer 2.
//       <i> Default: 1000  (1ms)
//       <i> Ignored if Detailed settings is selected
//     <e2.1> TIM2 detailed settings
//--------------------------------------------------------------------------- Timer 2 detailed settings
//       <o21> TIM2.PSC: Timer 2 Prescaler <0-65535>
//         <i> Set the prescaler for Timer 2.
//       <o22> TIM2.ARR: Timer 2 Auto-reload <0-65535>
//         <i> Set the Auto-reload for Timer 2.
//       <h> Timer 2 Control Register 1 Configuration (TIM2_CR1)
//         <o23.8..9> TIM2_CR1.CKD: Clock division   
//           <i> Default: tDTS = tCK_INT
//           <i> devision ratio between timer clock and dead time
//                     <0=> tDTS = tCK_INT
//                     <1=> tDTS = 2*tCK_INT
//                     <2=> tDTS = 4*tCK_INT
//         <o23.7> TIM2_CR1.ARPE: Auto-reload preload enable
//           <i> Default: Auto-reload preload disenabled
//         <o23.5..6> TIM2_CR1.CMS: Center aligned mode selection   
//           <i> Default: Edge-aligned
//                     <0=> Edge-aligned
//                     <1=> Center-aligned mode1
//                     <2=> Center-aligned mode2
//                     <3=> Center-aligned mode3
//         <o23.4> TIM2_CR1.DIR: Direction
//           <i> Default: DIR = Counter used as up-counter
//           <i> read only if timer is configured as Center-aligned or Encoder mode   
//                     <0=> Counter used as up-counter
//                     <1=> Counter used as down-counter
//         <o23.3> TIM2_CR1.OPM: One pulse mode enable
//           <i> Default: One pulse mode disabled
//         <o23.2> TIM2_CR1.URS: Update request source   
//           <i> Default: URS = Counter over-/underflow, UG bit, Slave mode controller
//                     <0=> Counter over-/underflow, UG bit, Slave mode controller
//                     <1=> Counter over-/underflow
//         <o23.1> TIM2_CR1.UDIS: Update disable
//           <i> Default: Update enabled
//       </h>
//
//       <h> Timer 2 Control Register 2 Configuration (TIM2_CR2)
//         <o24.7> TIM2_CR2.TI1S: TI1 Selection  
//           <i> Default: TIM2CH1 connected to TI1 input
//                     <0=> TIM2CH1 connected to TI1 input
//                     <1=> TIM2CH1,CH2,CH3 connected to TI1 input
//         <o24.4..6> TIM2_CR2.MMS: Master Mode Selection  
//           <i> Default: Reset
//           <i> Select information to be sent in master mode to slave timers for synchronisation
//                     <0=> Reset
//                     <1=> Enable
//                     <2=> Update
//                     <3=> Compare Pulse
//                     <4=> Compare OC1REF iused as TRGO
//                     <5=> Compare OC2REF iused as TRGO
//                     <6=> Compare OC3REF iused as TRGO
//                     <7=> Compare OC4REF iused as TRGO
//         <o24.3> TIM2_CR2.CCDS: Capture/Compare DMA Selection  
//           <i> Default: CC4 DMA request on CC4 event
//                     <0=> CC4 DMA request on CC4 event
//                     <1=> CC4 DMA request on update event
//       </h>
//
//       <h> Timer 2 Slave mode control register Configuration (TIM2_SMC)
//         <o25.15> TIM2_SMCR.ETP: External trigger polarity
//           <i> Default: ETR is non-inverted
//                     <0=> ETR is non-inverted
//                     <1=> ETR is inverted
//         <o25.14> TIM2_SMCR.ECE: External clock mode 2 enabled
//         <o25.12..13> TIM2_SMCR.ETPS: External trigger prescaler  
//           <i> Default: Prescaler OFF
//                     <0=> Prescaler OFF
//                     <1=> fETPR/2
//                     <2=> fETPR/4
//                     <3=> fETPR/8
//         <o25.8..11> TIM2_SMCR.ETF: External trigger filter  
//           <i> Default: No filter
//                     <0=>  No filter
//                     <1=>  fSampling=fCK_INT, N=2
//                     <2=>  fSampling=fCK_INT, N=4
//                     <3=>  fSampling=fCK_INT, N=8
//                     <4=>  fSampling=fDTS/2, N=6
//                     <5=>  fSampling=fDTS/2, N=8
//                     <6=>  fSampling=fDTS/4, N=6
//                     <7=>  fSampling=fDTS/4, N=8
//                     <8=>  fSampling=fDTS/8, N=6
//                     <9=>  fSampling=fDTS/8, N=8
//                     <10=> fSampling=fDTS/16, N=5
//                     <11=> fSampling=fDTS/16, N=6
//                     <12=> fSampling=fDTS/16, N=8
//                     <13=> fSampling=fDTS/32, N=5
//                     <14=> fSampling=fDTS/32, N=6
//                     <15=> fSampling=fDTS/32, N=8
//         <o25.7> TIM2_SMCR.MSM: Delay trigger input  
//         <o25.4..6> TIM2_SMCR.TS: Trigger Selection  
//           <i> Default: TIM1 (ITR0)
//                     <0=> TIM1 (ITR0)
//                     <1=> TIM2 (ITR1)
//                     <2=> TIM3 (ITR2)
//                     <3=> TIM4 (ITR3)
//                     <4=> TI1 Edge Detector (TI1F_ED)
//                     <5=> Filtered Timer Input 1 (TI1FP1)
//                     <6=> Filtered Timer Input 2 (TI1FP2)
//                     <7=> External Trigger Input (ETRF)
//         <o25.0..2> TIM2_SMCR.SMS: Slave mode selection   
//           <i> Default: Slave mode disabled
//                     <0=> Slave mode disabled
//                     <1=> Encoder mode 1
//                     <2=> Encoder mode 2
//                     <3=> Encoder mode 3
//                     <4=> Reset mode
//                     <5=> Gated mode
//                     <6=> Trigger mode
//                     <7=> External clock mode 1
//       </h>
//
//
//--------------------------------------------------------------------------- Timer 2 channel 1
//       <h> Channel 1 Configuration
//         <h> Cannel configured as output
//           <o26.7> TIM2_CCMR1.OC1CE: Output Compare 1 Clear enabled  
//           <o26.4..6> TIM2_CCMR1.OC1M: Output Compare 1 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 1 to active level on match
//                       <2=>  Set channel 1 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o26.3> TIM2_CCMR1.OC1PE: Output Compare 1 Preload enabled  
//           <o26.2> TIM2_CCMR1.OC1FE: Output Compare 1 Fast enabled  
//           <o26.0..1> TIM2_CCMR1.CC1S: Capture/compare 1 selection   
//             <i> Default: CC1 configured as output
//                       <0=> CC1 configured as output
//           <o28.1>  TIM2_CCER.CC1P: Capture/compare 1 output Polarity set  
//             <i> Default: OC1 active high
//                       <0=> OC1 active high
//                       <1=> OC1 active low
//           <o28.0>  TIM1_CCER.CC1E: Capture/compare 1 output enabled   
//             <i> Default: OC1 not active
//                       <0=> OC1 not active
//                       <1=> OC1 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o26.4..7> TIM2_CCMR1.IC1F: Input Capture 1 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o26.2..3> TIM2_CCMR1.IC1PSC: Input Capture 1 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o26.0..1> TIM2_CCMR1.CC1S: Capture/compare 1 selection   
//             <i> Default: CC1 configured as output
//                       <0=> CC1 configured as output
//                       <1=> CC1 configured as input, IC1 mapped on TI1
//                       <2=> CC1 configured as input, IC1 mapped on TI2
//                       <3=> CC1 configured as input, IC1 mapped on TRGI
//           <o28.1>  TIM2_CCER.CC1P: Capture/compare 1 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o28.0>  TIM2_CCER.CC1E: Capture/compare 1 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o29> TIM2_CCR1: Capture/compare register 1 <0-65535>
//         <i> Set the Compare register value for compare register 1.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 2 channel 2
//       <h> Channel 2 Configuration
//         <h> Cannel configured as output
//           <o26.15> TIM2_CCMR1.OC2CE: Output Compare 2 Clear enabled  
//           <o26.12..14> TIM2_CCMR1.OC2M: Output Compare 2 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 2 to active level on match
//                       <2=>  Set channel 2 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o26.11> TIM2_CCMR1.OC2PE: Output Compare 2 Preload enabled  
//           <o26.10> TIM2_CCMR1.OC2FE: Output Compare 2 Fast enabled  
//           <o26.8..9> TIM2_CCMR1.CC2S: Capture/compare 2 selection   
//             <i> Default: CC2 configured as output
//                       <0=> CC2 configured as output
//           <o28.5>  TIM2_CCER.CC2P: Capture/compare 2 output Polarity set  
//             <i> Default: OC2 active high
//                       <0=> OC2 active high
//                       <1=> OC2 active low
//           <o28.4>  TIM2_CCER.CC2E: Capture/compare 2 output enabled   
//             <i> Default: OC2 not active
//                       <0=> OC2 not active
//                       <1=> OC2 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o26.12..15> TIM2_CCMR1.IC2F: Input Capture 2 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o26.10..11> TIM2_CCMR1.IC2PSC: Input Capture 2 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o26.8..9> TIM2_CCMR1.CC2S: Capture/compare 2 selection   
//             <i> Default: CC2 configured as output
//                       <0=> CC2 configured as output
//                       <1=> CC2 configured as input, IC2 mapped on TI2
//                       <2=> CC2 configured as input, IC2 mapped on TI1
//                       <3=> CC2 configured as input, IC2 mapped on TRGI
//           <o28.5>  TIM2_CCER.CC2P: Capture/compare 2 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o28.4>  TIM2_CCER.CC2E: Capture/compare 2 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o30> TIM2_CCR2: Capture/compare register 2 <0-65535>
//         <i> Set the Compare register value for compare register 2.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 2 channel 3
//       <h> Channel 3 Configuration
//         <h> Cannel configured as output
//           <o27.7> TIM2_CCMR2.OC3CE: Output Compare 3 Clear enabled  
//           <o27.4..6> TIM2_CCMR2.OC3M: Output Compare 3 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 3 to active level on match
//                       <2=>  Set channel 3 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o27.3> TIM2_CCMR2.OC3PE: Output Compare 3 Preload enabled  
//           <o27.2> TIM2_CCMR2.OC3FE: Output Compare 3 Fast enabled  
//           <o27.0..1> TIM2_CCMR2.CC3S: Capture/compare 3 selection   
//             <i> Default: CC3 configured as output
//                       <0=> CC3 configured as output
//           <o28.9>  TIM2_CCER.CC3P: Capture/compare 3 output Polarity set  
//             <i> Default: OC3 active high
//                       <0=> OC3 active high
//                       <1=> OC3 active low
//           <o28.8>  TIM2_CCER.CC3E: Capture/compare 3 output enabled   
//             <i> Default: OC3 not active
//                       <0=> OC3 not active
//                       <1=> OC3 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o27.4..7> TIM2_CCMR2.IC3F: Input Capture 3 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o27.2..3> TIM2_CCMR2.IC3PSC: Input Capture 3 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o27.0..1> TIM2_CCMR2.CC3S: Capture/compare 3 selection   
//             <i> Default: CC3 configured as output
//                       <0=> CC3 configured as output
//                       <1=> CC3 configured as input, IC3 mapped on TI3
//                       <2=> CC3 configured as input, IC3 mapped on TI4
//                       <3=> CC3 configured as input, IC3 mapped on TRGI
//           <o28.9>  TIM2_CCER.CC3P: Capture/compare 3 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o28.8>  TIM2_CCER.CC3E: Capture/compare 3 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o31> TIM2_CCR3: Capture/compare register 3 <0-65535>
//         <i> Set the Compare register value for compare register 3.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 2 channel 4
//       <h> Channel 4 Configuration
//         <h> Cannel configured as output
//           <o27.15> TIM2_CCMR2.OC4CE: Output Compare 4 Clear enabled  
//           <o27.12..14> TIM2_CCMR2.OC4M: Output Compare 4 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 4 to active level on match
//                       <2=>  Set channel 4 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o27.11> TIM2_CCMR2.OC4PE: Output Compare 4 Preload enabled  
//           <o27.10> TIM2_CCMR2.OC4FE: Output Compare 4 Fast enabled  
//           <o27.8..9> TIM2_CCMR2.CC4S: Capture/compare 4 selection   
//             <i> Default: CC4 configured as output
//                       <0=> CC4 configured as output
//           <o28.13>  TIM2_CCER.CC4P: Capture/compare 4 output Polarity set  
//             <i> Default: OC4 active high
//                       <0=> OC4 active high
//                       <1=> OC4 active low
//           <o28.12>  TIM2_CCER.CC4E: Capture/compare 4 output enabled   
//             <i> Default: OC4 not active
//                       <0=> OC4 not active
//                       <1=> OC4 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o27.12..15> TIM2_CCMR2.IC4F: Input Capture 4 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o27.10..11> TIM2_CCMR2.IC4PSC: Input Capture 4 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o27.8..9> TIM2_CCMR2.CC4S: Capture/compare 4 selection   
//             <i> Default: CC4 configured as output
//                       <0=> CC4 configured as output
//                       <1=> CC4 configured as input, IC4 mapped on TI4
//                       <2=> CC4 configured as input, IC4 mapped on TI3
//                       <3=> CC4 configured as input, IC4 mapped on TRGI
//           <o28.13>  TIM2_CCER.CC4P: Capture/compare 4 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o28.12>  TIM2_CCER.CC4E: Capture/compare 4 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o32> TIM2_CCR4: Capture/compare register 4 <0-65535>
//         <i> Set the Compare register value for compare register 4.
//         <i> Default: 0
//     </h>
//
//     </e>
//     <e3.1> TIM2 interrupts
//       <o33.14> TIM2_DIER.TDE: Trigger DMA request enabled
//       <o33.12> TIM2_DIER.CC4DE: Capture/Compare 4 DMA request enabled
//       <o33.11> TIM2_DIER.CC3DE: Capture/Compare 3 DMA request enabled
//       <o33.10> TIM2_DIER.CC2DE: Capture/Compare 2 DMA request enabled
//       <o33.9>  TIM2_DIER.CC1DE: Capture/Compare 1 DMA request enabled
//       <o33.8>  TIM2_DIER.UDE: Update DMA request enabled
//       <o33.6>  TIM2_DIER.TIE: Trigger interrupt enabled
//       <o33.4>  TIM2_DIER.CC4IE: Capture/Compare 4 interrupt enabled
//       <o33.3>  TIM2_DIER.CC3IE: Capture/Compare 3 interrupt enabled
//       <o33.2>  TIM2_DIER.CC2IE: Capture/Compare 2 interrupt enabled
//       <o33.1>  TIM2_DIER.CC1IE: Capture/Compare 1 interrupt enabled
//       <o33.0>  TIM2_DIER.UIE: Update interrupt enabled
//     </e>
//   </e>
//--------------------------------------------------------------------------- Timer 3 enabled
//   <e1.2> TIM3 : Timer 3 enabled
//     <o34> TIM3 period [us] <1-72000000:10>
//       <i> Set the timer period for Timer 3.
//       <i> Default: 1000  (1ms)
//       <i> Ignored if Detailed settings is selected
//--------------------------------------------------------------------------- Timer 3 detailed settings
//     <e2.2> TIM3 detailed settings
//       <o35> TIM3.PSC: Timer 3 Prescaler <0-65535>
//         <i> Set the prescaler for Timer 3.
//       <o36> TIM3.ARR: Timer 3 Auto-reload <0-65535>
//         <i> Set the Auto-reload for Timer 3.
//       <h> Timer 3 Control Register 1 Configuration (TIM3_CR1)
//         <o37.8..9> TIM3_CR1.CKD: Clock division   
//           <i> Default: tDTS = tCK_INT
//           <i> devision ratio between timer clock and dead time
//                     <0=> tDTS = tCK_INT
//                     <1=> tDTS = 2*tCK_INT
//                     <2=> tDTS = 4*tCK_INT
//         <o37.7> TIM3_CR1.ARPE: Auto-reload preload enable
//           <i> Default: Auto-reload preload disenabled
//         <o37.5..6> TIM3_CR1.CMS: Center aligned mode selection   
//           <i> Default: Edge-aligned
//                     <0=> Edge-aligned
//                     <1=> Center-aligned mode1
//                     <2=> Center-aligned mode2
//                     <3=> Center-aligned mode3
//         <o37.4> TIM3_CR1.DIR: Direction
//           <i> Default: DIR = Counter used as up-counter
//           <i> read only if timer is configured as Center-aligned or Encoder mode   
//                     <0=> Counter used as up-counter
//                     <1=> Counter used as down-counter
//         <o37.3> TIM3_CR1.OPM: One pulse mode enable
//           <i> Default: One pulse mode disabled
//         <o37.2> TIM3_CR1.URS: Update request source   
//           <i> Default: URS = Counter over-/underflow, UG bit, Slave mode controller
//                     <0=> Counter over-/underflow, UG bit, Slave mode controller
//                     <1=> Counter over-/underflow
//         <o37.1> TIM3_CR1.UDIS: Update disable
//           <i> Default: Update enabled
//       </h>
//
//       <h> Timer 3 Control Register 2 Configuration (TIM3_CR2)
//         <o38.7> TIM3_CR2.TI1S: TI1 Selection  
//           <i> Default: TIM3CH1 connected to TI1 input
//                     <0=> TIM3CH1 connected to TI1 input
//                     <1=> TIM3CH1,CH2,CH3 connected to TI1 input
//         <o38.4..6> TIM3_CR2.MMS: Master Mode Selection  
//           <i> Default: Reset
//           <i> Select information to be sent in master mode to slave timers for synchronisation
//                     <0=> Reset
//                     <1=> Enable
//                     <2=> Update
//                     <3=> Compare Pulse
//                     <4=> Compare OC1REF iused as TRGO
//                     <5=> Compare OC2REF iused as TRGO
//                     <6=> Compare OC3REF iused as TRGO
//                     <7=> Compare OC4REF iused as TRGO
//         <o38.3> TIM3_CR2.CCDS: Capture/Compare DMA Selection  
//           <i> Default: CC4 DMA request on CC4 event
//                     <0=> CC4 DMA request on CC4 event
//                     <1=> CC4 DMA request on update event
//       </h>
//
//       <h> Timer 3 Slave mode control register Configuration (TIM3_SMC)
//         <o39.15> TIM3_SMCR.ETP: External trigger polarity
//           <i> Default: ETR is non-inverted
//                     <0=> ETR is non-inverted
//                     <1=> ETR is inverted
//         <o39.14> TIM3_SMCR.ECE: External clock mode 2 enabled
//         <o39.12..13> TIM3_SMCR.ETPS: External trigger prescaler  
//           <i> Default: Prescaler OFF
//                     <0=> Prescaler OFF
//                     <1=> fETPR/2
//                     <2=> fETPR/4
//                     <3=> fETPR/8
//         <o39.8..11> TIM3_SMCR.ETF: External trigger filter  
//           <i> Default: No filter
//                     <0=>  No filter
//                     <1=>  fSampling=fCK_INT, N=2
//                     <2=>  fSampling=fCK_INT, N=4
//                     <3=>  fSampling=fCK_INT, N=8
//                     <4=>  fSampling=fDTS/2, N=6
//                     <5=>  fSampling=fDTS/2, N=8
//                     <6=>  fSampling=fDTS/4, N=6
//                     <7=>  fSampling=fDTS/4, N=8
//                     <8=>  fSampling=fDTS/8, N=6
//                     <9=>  fSampling=fDTS/8, N=8
//                     <10=> fSampling=fDTS/16, N=5
//                     <11=> fSampling=fDTS/16, N=6
//                     <12=> fSampling=fDTS/16, N=8
//                     <13=> fSampling=fDTS/32, N=5
//                     <14=> fSampling=fDTS/32, N=6
//                     <15=> fSampling=fDTS/32, N=8
//         <o39.7> TIM3_SMCR.MSM: Delay trigger input  
//         <o39.4..6> TIM3_SMCR.TS: Trigger Selection  
//           <i> Default: TIM1 (ITR0)
//                     <0=> TIM1 (ITR0)
//                     <1=> TIM2 (ITR1)
//                     <2=> TIM3 (ITR2)
//                     <3=> TIM4 (ITR3)
//                     <4=> TI1 Edge Detector (TI1F_ED)
//                     <5=> Filtered Timer Input 1 (TI1FP1)
//                     <6=> Filtered Timer Input 2 (TI1FP2)
//                     <7=> External Trigger Input (ETRF)
//         <o39.0..2> TIM3_SMCR.SMS: Slave mode selection   
//           <i> Default: Slave mode disabled
//                     <0=> Slave mode disabled
//                     <1=> Encoder mode 1
//                     <2=> Encoder mode 2
//                     <3=> Encoder mode 3
//                     <4=> Reset mode
//                     <5=> Gated mode
//                     <6=> Trigger mode
//                     <7=> External clock mode 1
//       </h>
//
//--------------------------------------------------------------------------- Timer 3 channel 1
//       <h> Channel 1 Configuration
//         <h> Cannel configured as output
//           <o40.7> TIM3_CCMR1.OC1CE: Output Compare 1 Clear enabled  
//           <o40.4..6> TIM3_CCMR1.OC1M: Output Compare 1 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 1 to active level on match
//                       <2=>  Set channel 1 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o40.3> TIM3_CCMR1.OC1PE: Output Compare 1 Preload enabled  
//           <o40.2> TIM3_CCMR1.OC1FE: Output Compare 1 Fast enabled  
//           <o40.0..1> TIM3_CCMR1.CC1S: Capture/compare 1 selection   
//             <i> Default: CC1 configured as output
//                       <0=> CC1 configured as output
//           <o42.1>  TIM3_CCER.CC1P: Capture/compare 1 output Polarity set  
//             <i> Default: OC1 active high
//                       <0=> OC1 active high
//                       <1=> OC1 active low
//           <o42.0>  TIM1_CCER.CC1E: Capture/compare 1 output enabled   
//             <i> Default: OC1 not active
//                       <0=> OC1 not active
//                       <1=> OC1 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o40.4..7> TIM3_CCMR1.IC1F: Input Capture 1 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o40.2..3> TIM3_CCMR1.IC1PSC: Input Capture 1 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o40.0..1> TIM3_CCMR1.CC1S: Capture/compare 1 selection   
//             <i> Default: CC1 configured as output
//                       <0=> CC1 configured as output
//                       <1=> CC1 configured as input, IC1 mapped on TI1
//                       <2=> CC1 configured as input, IC1 mapped on TI2
//                       <3=> CC1 configured as input, IC1 mapped on TRGI
//           <o42.1>  TIM3_CCER.CC1P: Capture/compare 1 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o42.0>  TIM3_CCER.CC1E: Capture/compare 1 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o43> TIM3_CCR1: Capture/compare register 1 <0-65535>
//         <i> Set the Compare register value for compare register 1.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 3 channel 2
//       <h> Channel 2 Configuration
//         <h> Cannel configured as output
//           <o40.15> TIM3_CCMR1.OC2CE: Output Compare 2 Clear enabled  
//           <o40.12..14> TIM3_CCMR1.OC2M: Output Compare 2 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 2 to active level on match
//                       <2=>  Set channel 2 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o40.11> TIM3_CCMR1.OC2PE: Output Compare 2 Preload enabled  
//           <o40.10> TIM3_CCMR1.OC2FE: Output Compare 2 Fast enabled  
//           <o40.8..9> TIM3_CCMR1.CC2S: Capture/compare 2 selection   
//             <i> Default: CC2 configured as output
//                       <0=> CC2 configured as output
//           <o42.5>  TIM3_CCER.CC2P: Capture/compare 2 output Polarity set  
//             <i> Default: OC2 active high
//                       <0=> OC2 active high
//                       <1=> OC2 active low
//           <o42.4>  TIM3_CCER.CC2E: Capture/compare 2 output enabled   
//             <i> Default: OC2 not active
//                       <0=> OC2 not active
//                       <1=> OC2 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o40.12..15> TIM3_CCMR1.IC2F: Input Capture 2 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o40.10..11> TIM3_CCMR1.IC2PSC: Input Capture 2 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o40.8..9> TIM3_CCMR1.CC2S: Capture/compare 2 selection   
//             <i> Default: CC2 configured as output
//                       <0=> CC2 configured as output
//                       <1=> CC2 configured as input, IC2 mapped on TI2
//                       <2=> CC2 configured as input, IC2 mapped on TI1
//                       <3=> CC2 configured as input, IC2 mapped on TRGI
//           <o42.5>  TIM3_CCER.CC2P: Capture/compare 2 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o42.4>  TIM3_CCER.CC2E: Capture/compare 2 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o44> TIM3_CCR2: Capture/compare register 2 <0-65535>
//         <i> Set the Compare register value for compare register 2.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 3 channel 3
//       <h> Channel 3 Configuration
//         <h> Cannel configured as output
//           <o41.7> TIM3_CCMR2.OC3CE: Output Compare 3 Clear enabled  
//           <o41.4..6> TIM3_CCMR2.OC3M: Output Compare 3 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 3 to active level on match
//                       <2=>  Set channel 3 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o41.3> TIM3_CCMR2.OC3PE: Output Compare 3 Preload enabled  
//           <o41.2> TIM3_CCMR2.OC3FE: Output Compare 3 Fast enabled  
//           <o41.0..1> TIM3_CCMR2.CC3S: Capture/compare 3 selection   
//             <i> Default: CC3 configured as output
//                       <0=> CC3 configured as output
//           <o42.9>  TIM3_CCER.CC3P: Capture/compare 3 output Polarity set  
//             <i> Default: OC3 active high
//                       <0=> OC3 active high
//                       <1=> OC3 active low
//           <o42.8>  TIM3_CCER.CC3E: Capture/compare 3 output enabled   
//             <i> Default: OC3 not active
//                       <0=> OC3 not active
//                       <1=> OC3 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o41.4..7> TIM3_CCMR2.IC3F: Input Capture 3 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o41.2..3> TIM3_CCMR2.IC3PSC: Input Capture 3 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o41.0..1> TIM3_CCMR2.CC3S: Capture/compare 3 selection   
//             <i> Default: CC3 configured as output
//                       <0=> CC3 configured as output
//                       <1=> CC3 configured as input, IC3 mapped on TI3
//                       <2=> CC3 configured as input, IC3 mapped on TI4
//                       <3=> CC3 configured as input, IC3 mapped on TRGI
//           <o42.9>  TIM3_CCER.CC3P: Capture/compare 3 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o42.8>  TIM3_CCER.CC3E: Capture/compare 3 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o45> TIM3_CCR3: Capture/compare register 3 <0-65535>
//         <i> Set the Compare register value for compare register 3.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 3 channel 4
//       <h> Channel 4 Configuration
//         <h> Cannel configured as output
//           <o41.15> TIM3_CCMR2.OC4CE: Output Compare 4 Clear enabled  
//           <o41.12..14> TIM3_CCMR2.OC4M: Output Compare 4 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 4 to active level on match
//                       <2=>  Set channel 4 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o41.11> TIM3_CCMR2.OC4PE: Output Compare 4 Preload enabled  
//           <o41.10> TIM3_CCMR2.OC4FE: Output Compare 4 Fast enabled  
//           <o41.8..9> TIM3_CCMR2.CC4S: Capture/compare 4 selection   
//             <i> Default: CC4 configured as output
//                       <0=> CC4 configured as output
//           <o42.13>  TIM3_CCER.CC4P: Capture/compare 4 output Polarity set  
//             <i> Default: OC4 active high
//                       <0=> OC4 active high
//                       <1=> OC4 active low
//           <o42.12>  TIM3_CCER.CC4E: Capture/compare 4 output enabled   
//             <i> Default: OC4 not active
//                       <0=> OC4 not active
//                       <1=> OC4 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o41.12..15> TIM3_CCMR2.IC4F: Input Capture 4 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o41.10..11> TIM3_CCMR2.IC4PSC: Input Capture 4 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o41.8..9> TIM3_CCMR2.CC4S: Capture/compare 4 selection   
//             <i> Default: CC4 configured as output
//                       <0=> CC4 configured as output
//                       <1=> CC4 configured as input, IC4 mapped on TI4
//                       <2=> CC4 configured as input, IC4 mapped on TI3
//                       <3=> CC4 configured as input, IC4 mapped on TRGI
//           <o42.13>  TIM3_CCER.CC4P: Capture/compare 4 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o42.12>  TIM3_CCER.CC4E: Capture/compare 4 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o46> TIM3_CCR4: Capture/compare register 4 <0-65535>
//         <i> Set the Compare register value for compare register 4.
//         <i> Default: 0
//     </h>
//
//     </e>
//     <e3.2> TIM3 interrupts
//       <o47.14> TIM3_DIER.TDE: Trigger DMA request enabled
//       <o47.12> TIM3_DIER.CC4DE: Capture/Compare 4 DMA request enabled
//       <o47.11> TIM3_DIER.CC3DE: Capture/Compare 3 DMA request enabled
//       <o47.10> TIM3_DIER.CC2DE: Capture/Compare 2 DMA request enabled
//       <o47.9>  TIM3_DIER.CC1DE: Capture/Compare 1 DMA request enabled
//       <o47.8>  TIM3_DIER.UDE: Update DMA request enabled
//       <o47.6>  TIM3_DIER.TIE: Trigger interrupt enabled
//       <o47.4>  TIM3_DIER.CC4IE: Capture/Compare 4 interrupt enabled
//       <o47.3>  TIM3_DIER.CC3IE: Capture/Compare 3 interrupt enabled
//       <o47.2>  TIM3_DIER.CC2IE: Capture/Compare 2 interrupt enabled
//       <o47.1>  TIM3_DIER.CC1IE: Capture/Compare 1 interrupt enabled
//       <o47.0>  TIM3_DIER.UIE: Update interrupt enabled
//     </e>
//   </e>
//
//--------------------------------------------------------------------------- Timer 4 enabled
//   <e1.3> TIM4 : Timer 4 enabled
//     <o48> TIM4 period [us] <1-72000000:10>
//       <i> Set the timer period for Timer 4.
//       <i> Default: 1000  (1ms)
//       <i> Ignored if detailed settings is selected
//--------------------------------------------------------------------------- Timer 4 detailed settings
//     <e2.3> TIM4 detailed settings
//       <o49> TIM4.PSC: Timer 4 Prescaler <0-65535>
//         <i> Set the prescaler for Timer 4.
//       <o50> TIM4.ARR: Timer 4 Auto-reload <0-65535>
//         <i> Set the Auto-reload for Timer 4.
//       <h> Timer 4 Control Register 1 Configuration (TIM4_CR1)
//         <o51.8..9> TIM4_CR1.CKD: Clock division   
//           <i> Default: tDTS = tCK_INT
//           <i> devision ratio between timer clock and dead time
//                     <0=> tDTS = tCK_INT
//                     <1=> tDTS = 2*tCK_INT
//                     <2=> tDTS = 4*tCK_INT
//         <o51.7> TIM4_CR1.ARPE: Auto-reload preload enable
//           <i> Default: Auto-reload preload disenabled
//         <o51.5..6> TIM4_CR1.CMS: Center aligned mode selection   
//           <i> Default: Edge-aligned
//                     <0=> Edge-aligned
//                     <1=> Center-aligned mode1
//                     <2=> Center-aligned mode2
//                     <3=> Center-aligned mode3
//         <o51.4> TIM4_CR1.DIR: Direction
//           <i> Default: DIR = Counter used as up-counter
//           <i> read only if timer is configured as Center-aligned or Encoder mode   
//                     <0=> Counter used as up-counter
//                     <1=> Counter used as down-counter
//         <o51.3> TIM4_CR1.OPM: One pulse mode enable
//           <i> Default: One pulse mode disabled
//         <o51.2> TIM4_CR1.URS: Update request source   
//           <i> Default: URS = Counter over-/underflow, UG bit, Slave mode controller
//                     <0=> Counter over-/underflow, UG bit, Slave mode controller
//                     <1=> Counter over-/underflow
//         <o51.1> TIM4_CR1.UDIS: Update disable
//           <i> Default: Update enabled
//       </h>
//
//       <h> Timer 4 Control Register 2 Configuration (TIM4_CR2)
//         <o52.7> TIM4_CR2.TI1S: TI1 Selection  
//           <i> Default: TIM4CH1 connected to TI1 input
//                     <0=> TIM4CH1 connected to TI1 input
//                     <1=> TIM4CH1,CH2,CH3 connected to TI1 input
//         <o52.4..6> TIM4_CR2.MMS: Master Mode Selection  
//           <i> Default: Reset
//           <i> Select information to be sent in master mode to slave timers for synchronisation
//                     <0=> Reset
//                     <1=> Enable
//                     <2=> Update
//                     <3=> Compare Pulse
//                     <4=> Compare OC1REF iused as TRGO
//                     <5=> Compare OC2REF iused as TRGO
//                     <6=> Compare OC3REF iused as TRGO
//                     <7=> Compare OC4REF iused as TRGO
//         <o52.3> TIM4_CR2.CCDS: Capture/Compare DMA Selection  
//           <i> Default: CC4 DMA request on CC4 event
//                     <0=> CC4 DMA request on CC4 event
//                     <1=> CC4 DMA request on update event
//       </h>
//
//       <h> Timer 4 Slave mode control register Configuration (TIM4_SMC)
//         <o53.15> TIM4_SMCR.ETP: External trigger polarity
//           <i> Default: ETR is non-inverted
//                     <0=> ETR is non-inverted
//                     <1=> ETR is inverted
//         <o53.14> TIM4_SMCR.ECE: External clock mode 2 enabled
//         <o53.12..13> TIM4_SMCR.ETPS: External trigger prescaler  
//           <i> Default: Prescaler OFF
//                     <0=> Prescaler OFF
//                     <1=> fETPR/2
//                     <2=> fETPR/4
//                     <3=> fETPR/8
//         <o53.8..11> TIM4_SMCR.ETF: External trigger filter  
//           <i> Default: No filter
//                     <0=>  No filter
//                     <1=>  fSampling=fCK_INT, N=2
//                     <2=>  fSampling=fCK_INT, N=4
//                     <3=>  fSampling=fCK_INT, N=8
//                     <4=>  fSampling=fDTS/2, N=6
//                     <5=>  fSampling=fDTS/2, N=8
//                     <6=>  fSampling=fDTS/4, N=6
//                     <7=>  fSampling=fDTS/4, N=8
//                     <8=>  fSampling=fDTS/8, N=6
//                     <9=>  fSampling=fDTS/8, N=8
//                     <10=> fSampling=fDTS/16, N=5
//                     <11=> fSampling=fDTS/16, N=6
//                     <12=> fSampling=fDTS/16, N=8
//                     <13=> fSampling=fDTS/32, N=5
//                     <14=> fSampling=fDTS/32, N=6
//                     <15=> fSampling=fDTS/32, N=8
//         <o53.7> TIM4_SMCR.MSM: Delay trigger input  
//         <o53.4..6> TIM4_SMCR.TS: Trigger Selection  
//           <i> Default: TIM1 (ITR0)
//                     <0=> TIM1 (ITR0)
//                     <1=> TIM2 (ITR1)
//                     <2=> TIM3 (ITR2)
//                     <3=> TIM4 (ITR3)
//                     <4=> TI1 Edge Detector (TI1F_ED)
//                     <5=> Filtered Timer Input 1 (TI1FP1)
//                     <6=> Filtered Timer Input 2 (TI1FP2)
//                     <7=> External Trigger Input (ETRF)
//         <o53.0..2> TIM4_SMCR.SMS: Slave mode selection   
//           <i> Default: Slave mode disabled
//                     <0=> Slave mode disabled
//                     <1=> Encoder mode 1
//                     <2=> Encoder mode 2
//                     <3=> Encoder mode 3
//                     <4=> Reset mode
//                     <5=> Gated mode
//                     <6=> Trigger mode
//                     <7=> External clock mode 1
//       </h>
//
//
//--------------------------------------------------------------------------- Timer 4 channel 1
//       <h> Channel 1 Configuration
//         <h> Cannel configured as output
//           <o54.7> TIM4_CCMR1.OC1CE: Output Compare 1 Clear enabled  
//           <o54.4..6> TIM4_CCMR1.OC1M: Output Compare 1 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 1 to active level on match
//                       <2=>  Set channel 1 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o54.3> TIM4_CCMR1.OC1PE: Output Compare 1 Preload enabled  
//           <o54.2> TIM4_CCMR1.OC1FE: Output Compare 1 Fast enabled  
//           <o54.0..1> TIM4_CCMR1.CC1S: Capture/compare 1 selection   
//             <i> Default: CC1 configured as output
//                       <0=> CC1 configured as output
//           <o56.1>  TIM4_CCER.CC1P: Capture/compare 1 output Polarity set  
//             <i> Default: OC1 active high
//                       <0=> OC1 active high
//                       <1=> OC1 active low
//           <o56.0>  TIM1_CCER.CC1E: Capture/compare 1 output enabled   
//             <i> Default: OC1 not active
//                       <0=> OC1 not active
//                       <1=> OC1 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o54.4..7> TIM4_CCMR1.IC1F: Input Capture 1 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o54.2..3> TIM4_CCMR1.IC1PSC: Input Capture 1 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o54.0..1> TIM4_CCMR1.CC1S: Capture/compare 1 selection   
//             <i> Default: CC1 configured as output
//                       <0=> CC1 configured as output
//                       <1=> CC1 configured as input, IC1 mapped on TI1
//                       <2=> CC1 configured as input, IC1 mapped on TI2
//                       <3=> CC1 configured as input, IC1 mapped on TRGI
//           <o56.1>  TIM4_CCER.CC1P: Capture/compare 1 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o56.0>  TIM4_CCER.CC1E: Capture/compare 1 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o57> TIM4_CCR1: Capture/compare register 1 <0-65535>
//         <i> Set the Compare register value for compare register 1.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 4 channel 2
//       <h> Channel 2 Configuration
//         <h> Cannel configured as output
//           <o54.15> TIM4_CCMR1.OC2CE: Output Compare 2 Clear enabled  
//           <o54.12..14> TIM4_CCMR1.OC2M: Output Compare 2 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 2 to active level on match
//                       <2=>  Set channel 2 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o54.11> TIM4_CCMR1.OC2PE: Output Compare 2 Preload enabled  
//           <o54.10> TIM4_CCMR1.OC2FE: Output Compare 2 Fast enabled  
//           <o54.8..9> TIM4_CCMR1.CC2S: Capture/compare 2 selection   
//             <i> Default: CC2 configured as output
//                       <0=> CC2 configured as output
//           <o56.5>  TIM4_CCER.CC2P: Capture/compare 2 output Polarity set  
//             <i> Default: OC2 active high
//                       <0=> OC2 active high
//                       <1=> OC2 active low
//           <o56.4>  TIM4_CCER.CC2E: Capture/compare 2 output enabled   
//             <i> Default: OC2 not active
//                       <0=> OC2 not active
//                       <1=> OC2 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o54.12..15> TIM4_CCMR1.IC2F: Input Capture 2 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o54.10..11> TIM4_CCMR1.IC2PSC: Input Capture 2 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o54.8..9> TIM4_CCMR1.CC2S: Capture/compare 2 selection   
//             <i> Default: CC2 configured as output
//                       <0=> CC2 configured as output
//                       <1=> CC2 configured as input, IC2 mapped on TI2
//                       <2=> CC2 configured as input, IC2 mapped on TI1
//                       <3=> CC2 configured as input, IC2 mapped on TRGI
//           <o56.5>  TIM4_CCER.CC2P: Capture/compare 2 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o56.4>  TIM4_CCER.CC2E: Capture/compare 2 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o58> TIM4_CCR2: Capture/compare register 2 <0-65535>
//         <i> Set the Compare register value for compare register 2.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 4 channel 3
//       <h> Channel 3 Configuration
//         <h> Cannel configured as output
//           <o55.7> TIM4_CCMR2.OC3CE: Output Compare 3 Clear enabled  
//           <o55.4..6> TIM4_CCMR2.OC3M: Output Compare 3 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 3 to active level on match
//                       <2=>  Set channel 3 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o55.3> TIM4_CCMR2.OC3PE: Output Compare 3 Preload enabled  
//           <o55.2> TIM4_CCMR2.OC3FE: Output Compare 3 Fast enabled  
//           <o55.0..1> TIM4_CCMR2.CC3S: Capture/compare 3 selection   
//             <i> Default: CC3 configured as output
//                       <0=> CC3 configured as output
//           <o56.9>  TIM4_CCER.CC3P: Capture/compare 3 output Polarity set  
//             <i> Default: OC3 active high
//                       <0=> OC3 active high
//                       <1=> OC3 active low
//           <o56.8>  TIM4_CCER.CC3E: Capture/compare 3 output enabled   
//             <i> Default: OC3 not active
//                       <0=> OC3 not active
//                       <1=> OC3 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o55.4..7> TIM4_CCMR2.IC3F: Input Capture 3 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o55.2..3> TIM4_CCMR2.IC3PSC: Input Capture 3 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o55.0..1> TIM4_CCMR2.CC3S: Capture/compare 3 selection   
//             <i> Default: CC3 configured as output
//                       <0=> CC3 configured as output
//                       <1=> CC3 configured as input, IC3 mapped on TI3
//                       <2=> CC3 configured as input, IC3 mapped on TI4
//                       <3=> CC3 configured as input, IC3 mapped on TRGI
//           <o56.9>  TIM4_CCER.CC3P: Capture/compare 3 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o56.8>  TIM4_CCER.CC3E: Capture/compare 3 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o59> TIM4_CCR3: Capture/compare register 3 <0-65535>
//         <i> Set the Compare register value for compare register 3.
//         <i> Default: 0
//     </h>
//
//--------------------------------------------------------------------------- Timer 4 channel 4
//       <h> Channel 4 Configuration
//         <h> Cannel configured as output
//           <o55.15> TIM4_CCMR2.OC4CE: Output Compare 4 Clear enabled  
//           <o55.12..14> TIM4_CCMR2.OC4M: Output Compare 4 Mode  
//             <i> Default: Frozen
//                       <0=>  Frozen
//                       <1=>  Set channel 4 to active level on match
//                       <2=>  Set channel 4 to inactive level on match
//                       <3=>  Toggle 
//                       <4=>  Force inactive level
//                       <5=>  Force active level
//                       <6=>  PWM mode 1
//                       <7=>  PWM mode 2
//           <o55.11> TIM4_CCMR2.OC4PE: Output Compare 4 Preload enabled  
//           <o55.10> TIM4_CCMR2.OC4FE: Output Compare 4 Fast enabled  
//           <o55.8..9> TIM4_CCMR2.CC4S: Capture/compare 4 selection   
//             <i> Default: CC4 configured as output
//                       <0=> CC4 configured as output
//           <o56.13>  TIM4_CCER.CC4P: Capture/compare 4 output Polarity set  
//             <i> Default: OC4 active high
//                       <0=> OC4 active high
//                       <1=> OC4 active low
//           <o56.12>  TIM4_CCER.CC4E: Capture/compare 4 output enabled   
//             <i> Default: OC4 not active
//                       <0=> OC4 not active
//                       <1=> OC4 is output on corresponding pin
//         </h>
//         <h> Channel configured as input
//           <o54.12..15> TIM4_CCMR2.IC4F: Input Capture 4 Filter  
//             <i> Default: No filter
//                       <0=>  No filter
//                       <1=>  fSampling=fCK_INT, N=2
//                       <2=>  fSampling=fCK_INT, N=4
//                       <3=>  fSampling=fCK_INT, N=8
//                       <4=>  fSampling=fDTS/2, N=6
//                       <5=>  fSampling=fDTS/2, N=8
//                       <6=>  fSampling=fDTS/4, N=6
//                       <7=>  fSampling=fDTS/4, N=8
//                       <8=>  fSampling=fDTS/8, N=6
//                       <9=>  fSampling=fDTS/8, N=8
//                       <10=> fSampling=fDTS/16, N=5
//                       <11=> fSampling=fDTS/16, N=6
//                       <12=> fSampling=fDTS/16, N=8
//                       <13=> fSampling=fDTS/32, N=5
//                       <14=> fSampling=fDTS/32, N=6
//                       <15=> fSampling=fDTS/32, N=8
//           <o54.10..11> TIM4_CCMR2.IC4PSC: Input Capture 4 Prescaler  
//             <i> Default: No prescaler
//                       <0=>  No prescaler
//                       <1=>  capture every 2 events
//                       <2=>  capture every 4 events
//                       <3=>  capture every 8 events 
//           <o54.8..9> TIM4_CCMR2.CC4S: Capture/compare 4 selection   
//             <i> Default: CC4 configured as output
//                       <0=> CC4 configured as output
//                       <1=> CC4 configured as input, IC4 mapped on TI4
//                       <2=> CC4 configured as input, IC4 mapped on TI3
//                       <3=> CC4 configured as input, IC4 mapped on TRGI
//           <o56.13>  TIM4_CCER.CC4P: Capture/compare 4 output Polarity set  
//             <i> Default: non-inverted
//                       <0=> non-inverted
//                       <1=> inverted
//           <o56.12>  TIM4_CCER.CC4E: Capture/compare 4 output enabled   
//             <i> Default: Capture disabled
//                       <0=> Capture disabled
//                       <1=> Capture enabled
//         </h>
//       <o60> TIM4_CCR4: Capture/compare register 4 <0-65535>
//         <i> Set the Compare register value for compare register 4.
//         <i> Default: 0
//     </h>
//
//     </e>
//     <e3.3> TIM4 interrupts
//       <o61.14> TIM4_DIER.TDE: Trigger DMA request enabled
//       <o61.12> TIM4_DIER.CC4DE: Capture/Compare 4 DMA request enabled
//       <o61.11> TIM4_DIER.CC3DE: Capture/Compare 3 DMA request enabled
//       <o61.10> TIM4_DIER.CC2DE: Capture/Compare 2 DMA request enabled
//       <o61.9>  TIM4_DIER.CC1DE: Capture/Compare 1 DMA request enabled
//       <o61.8>  TIM4_DIER.UDE: Update DMA request enabled
//       <o61.6>  TIM4_DIER.TIE: Trigger interrupt enabled
//       <o61.4>  TIM4_DIER.CC4IE: Capture/Compare 4 interrupt enabled
//       <o61.3>  TIM4_DIER.CC3IE: Capture/Compare 3 interrupt enabled
//       <o61.2>  TIM4_DIER.CC2IE: Capture/Compare 2 interrupt enabled
//       <o61.1>  TIM4_DIER.CC1IE: Capture/Compare 1 interrupt enabled
//       <o61.0>  TIM4_DIER.UIE: Update interrupt enabled
//     </e>
// 
//
//   </e>
// </e> End of Timer Configuration
#define __TIMER_SETUP             0                       //  0
#define __TIMER_USED              0x0000                  //  1
#define __TIMER_DETAILS           0x0000                  //  2
#define __TIMER_INTERRUPTS        0x0000                  //  3
#define __TIM1_PERIOD             0x00064                 //  4
#define __TIM1_PSC                0x0000                  //  5
#define __TIM1_ARR                0x0004                  //  6
#define __TIM1_RCR                0x0000                  //  7
#define __TIM1_CR1                0x0004                  //  8
#define __TIM1_CR2                0x0000                  //  9
#define __TIM1_SMCR               0x0000                  // 10
#define __TIM1_CCMR1              0x0061                  // 11
#define __TIM1_CCMR2              0x0068                  // 12
#define __TIM1_CCER               0x0000                  // 13
#define __TIM1_CCR1               0x0000                  // 14
#define __TIM1_CCR2               0x0000                  // 15
#define __TIM1_CCR3               0x0000                  // 16
#define __TIM1_CCR4               0x0000                  // 17
#define __TIM1_BDTR               0x0000                  // 18
#define __TIM1_DIER               0x0000                  // 19
#define __TIM2_PERIOD             0xB71B0                 // 20
#define __TIM2_PSC                0x0000                  // 21
#define __TIM2_ARR                0x0004                  // 22
#define __TIM2_CR1                0x0004                  // 23
#define __TIM2_CR2                0x0000                  // 24
#define __TIM2_SMCR               0x0000                  // 25
#define __TIM2_CCMR1              0x0000                  // 26
#define __TIM2_CCMR2              0x0000                  // 27
#define __TIM2_CCER               0x0000                  // 28
#define __TIM2_CCR1               0x0000                  // 29
#define __TIM2_CCR2               0x0000                  // 30
#define __TIM2_CCR3               0x0000                  // 31
#define __TIM2_CCR4               0x0000                  // 32
#define __TIM2_DIER               0x0000                  // 33
#define __TIM3_PERIOD             0x7A120                 // 34
#define __TIM3_PSC                0x0000                  // 35
#define __TIM3_ARR                0x0004                  // 36
#define __TIM3_CR1                0x0000                  // 37
#define __TIM3_CR2                0x0000                  // 38
#define __TIM3_SMCR               0x0000                  // 39
#define __TIM3_CCMR1              0x0000                  // 40
#define __TIM3_CCMR2              0x0000                  // 41
#define __TIM3_CCER               0x0000                  // 42
#define __TIM3_CCR1               0x0000                  // 43
#define __TIM3_CCR2               0x0000                  // 44
#define __TIM3_CCR3               0x0000                  // 45
#define __TIM3_CCR4               0x0000                  // 46
#define __TIM3_DIER               0x0000                  // 47
#define __TIM4_PERIOD             0x003E8                 // 48
#define __TIM4_PSC                0x1C1F                  // 49
#define __TIM4_ARR                0x0063                  // 50
#define __TIM4_CR1                0x0004                  // 51
#define __TIM4_CR2                0x0000                  // 52
#define __TIM4_SMCR               0x0000                  // 53
#define __TIM4_CCMR1              0x0000                  // 54
#define __TIM4_CCMR2              0x6060                  // 55
#define __TIM4_CCER               0x1100                  // 56
#define __TIM4_CCR1               0x0000                  // 57
#define __TIM4_CCR2               0x0000                  // 58
#define __TIM4_CCR3               0x0000                  // 59
#define __TIM4_CCR4               0x0064                  // 60
#define __TIM4_DIER               0x0000                  // 61


//=========================================================================== USART Configuration
// <e0> USART Configuration
//--------------------------------------------------------------------------- USART1
//   <e1.0> USART1 : USART #1 enable
//     <o4> Baudrate 
//          <9600=>    9600 Baud
//          <14400=>   14400 Baud
//          <19200=>   19200 Baud
//          <28800=>   28800 Baud
//          <38400=>   38400 Baud
//          <56000=>   56000 Baud
//          <57600=>   57600 Baud
//          <115200=>  115200 Baud
//     <o5.12> Data Bits 
//          <0=>       8 Data Bits
//          <1=>       9 Data Bits
//     <o6.12..13> Stop Bits
//          <1=>     0.5 Stop Bit
//          <0=>       1 Stop Bit
//          <3=>     1.5 Stop Bits
//          <2=>       2 Stop Bits
//     <o7.9..10> Parity 
//          <0=>         No Parity
//          <2=>         Even Parity
//          <3=>         Odd Parity
//     <o8.8..9> Flow Control
//          <0=>         None
//          <3=>         Hardware
//     <o9.2> Pins used
//          <0=>         TX = PA9, RX = PA10
//          <1=>         TX = PB6, RX = PB7
//     <e3.0> USART1 interrupts
//       <o10.4> USART1_CR1.IDLEIE: IDLE Interrupt enable
//       <o10.5> USART1_CR1.RXNEIE: RXNE Interrupt enable
//       <o10.6> USART1_CR1.TCIE: Transmission Complete Interrupt enable
//       <o10.7> USART1_CR1.TXEIE: TXE Interrupt enable
//       <o10.8> USART1_CR1.PEIE: PE Interrupt enable
//       <o11.6> USART1_CR2.LBDIE: LIN Break Detection Interrupt enable
//       <o12.0> USART1_CR3.EIE: Error Interrupt enable
//       <o12.10> USART1_CR3.CTSIE: CTS Interrupt enable
//     </e>
//   </e>

//--------------------------------------------------------------------------- USART2
//   <e1.1> USART2 : USART #2 enable
//     <o13> Baudrate 
//          <9600=>    9600 Baud
//          <14400=>   14400 Baud
//          <19200=>   19200 Baud
//          <28800=>   28800 Baud
//          <38400=>   38400 Baud
//          <56000=>   56000 Baud
//          <57600=>   57600 Baud
//          <115200=>  115200 Baud
//     <o14.12> Data Bits 
//          <0=>       8 Data Bits
//          <1=>       9 Data Bits
//     <o15.12..13> Stop Bits
//          <1=>     0.5 Stop Bit
//          <0=>       1 Stop Bit
//          <3=>     1.5 Stop Bits
//          <2=>       2 Stop Bits
//     <o16.9..10> Parity 
//          <0=>         No Parity
//          <2=>         Even Parity
//          <3=>         Odd Parity
//     <o17.8..9> Flow Control
//          <0=>         None
//          <3=>         Hardware
//     <o18.3> Pins used
//          <0=>         CTS = PA0, RTS = PA1, TX = PA2, RX = PA3 
//          <1=>         CTS = PD3, RTS = PD4, TX = PD5, RX = PD6 
//     <e3.1> USART2 interrupts
//       <o19.4> USART1_CR2.IDLEIE: IDLE Interrupt enable
//       <o19.5> USART1_CR2.RXNEIE: RXNE Interrupt enable
//       <o19.6> USART1_CR2.TCIE: Transmission Complete Interrupt enable
//       <o19.7> USART1_CR2.TXEIE: TXE Interrupt enable
//       <o19.8> USART1_CR2.PEIE: PE Interrupt enable
//       <o20.6> USART1_CR2.LBDIE: LIN Break Detection Interrupt enable
//       <o21.0> USART1_CR2.EIE: Error Interrupt enable
//       <o21.10> USART1_CR2.CTSIE: CTS Interrupt enable
//     </e>
//   </e>

//--------------------------------------------------------------------------- USART3
//   <e1.2> USART3 : USART #3 enable
//     <o22> Baudrate 
//          <9600=>    9600 Baud
//          <14400=>   14400 Baud
//          <19200=>   19200 Baud
//          <28800=>   28800 Baud
//          <38400=>   38400 Baud
//          <56000=>   56000 Baud
//          <57600=>   57600 Baud
//          <115200=>  115200 Baud
//     <o23.12> Data Bits 
//          <0=>       8 Data Bits
//          <1=>       9 Data Bits
//     <o24.12..13> Stop Bits
//          <1=>     0.5 Stop Bit
//          <0=>       1 Stop Bit
//          <3=>     1.5 Stop Bits
//          <2=>       2 Stop Bits
//     <o25.9..10> Parity 
//          <0=>         No Parity
//          <2=>         Even Parity
//          <3=>         Odd Parity
//     <o26.8..9> Flow Control
//          <0=>         None
//          <3=>         Hardware
//     <o27.4..5> Pins used
//          <0=>         TX = PB10, RX = PB11, CTS = PB13, RTS = PB14  
//          <1=>         TX = PC10, RX = PC11, CTS = PB13, RTS = PB14  
//          <3=>         TX = PD8,  RX = PD9,  CTS = PD11, RTS = PB12  
//     <e3.2> USART3 interrupts
//       <o28.4> USART3_CR1.IDLEIE: IDLE Interrupt enable
//       <o28.5> USART3_CR1.RXNEIE: RXNE Interrupt enable
//       <o28.6> USART3_CR1.TCIE: Transmission Complete Interrupt enable
//       <o28.7> USART3_CR1.TXEIE: TXE Interrupt enable
//       <o28.8> USART3_CR1.PEIE: PE Interrupt enable
//       <o29.6> USART3_CR2.LBDIE: LIN Break Detection Interrupt enable
//       <o30.0> USART3_CR3.EIE: Error Interrupt enable
//       <o30.10> USART3_CR3.CTSIE: CTS Interrupt enable
//     </e>
//   </e>
// </e> End of USART Configuration
#define __USART_SETUP             0                       //  0
#define __USART_USED              0x00                    //  1
#define __USART_DETAILS           0x00					  //  2
#define __USART_INTERRUPTS        0x00					  //  3
#define __USART1_BAUDRATE         9600					  //  4
#define __USART1_DATABITS         0x00000000
#define __USART1_STOPBITS         0x00000000
#define __USART1_PARITY           0x00000000
#define __USART1_FLOWCTRL         0x00000000
#define __USART1_REMAP            0x00000000
#define __USART1_CR1              0x00000000
#define __USART1_CR2              0x00000000
#define __USART1_CR3              0x00000000
#define __USART2_BAUDRATE         115200                    // 13
#define __USART2_DATABITS         0x00000000
#define __USART2_STOPBITS         0x00000000
#define __USART2_PARITY           0x00000000
#define __USART2_FLOWCTRL         0x00000000
#define __USART2_REMAP            0x00000000
#define __USART2_CR1              0x00000000
#define __USART2_CR2              0x00000000
#define __USART2_CR3              0x00000000
#define __USART3_BAUDRATE         9600                    // 22
#define __USART3_DATABITS         0x00000000
#define __USART3_STOPBITS         0x00000000
#define __USART3_PARITY           0x00000000
#define __USART3_FLOWCTRL         0x00000000
#define __USART3_REMAP            0x00000000
#define __USART3_CR1              0x00000000
#define __USART3_CR2              0x00000000
#define __USART3_CR3              0x00000000


//=========================================================================== Tamper Configuration
// <e0> Tamper Configuration
//   <o1.0> Tamper Pin enable
//   <o1.1> Tamper pin active level
//      <i> Default: active level = HIGH
//        <0=>       active level = HIGH
//        <1=>       active level = LOW
//   <o2.2> Tamper interrupt enable
// </e> End of Tamper Configuration
#define __TAMPER_SETUP            0                       //  0
#define __BKP_CR                  0x00000000              //  1
#define __BKP_CSR                 0x00000000              //  2


//=========================================================================== External interrupt/event Configuration
// <e0> External interrupt/event Configuration
//--------------------------------------------------------------------------- EXTI line 0
//   <e1.0> EXTI0: EXTI line 0 enable
//     <o2.0> interrupt enable
//     <o3.0> generate interrupt
//     <o4.0> generate event
//     <o5.0> use rising trigger for interrupt/event
//     <o6.0> use falling trigger for interrupt/event
//     <o7.0..3> use pin for for interrupt/event
//        <i> Default: pin = PA0
//          <0=>         pin = PA0
//          <1=>         pin = PB0
//          <2=>         pin = PC0
//          <3=>         pin = PD0
//          <4=>         pin = PE0
//          <5=>         pin = PF0
//          <6=>         pin = PG0
//   </e>

//--------------------------------------------------------------------------- EXTI line 1
//   <e1.1> EXTI1: EXTI line 1 enable
//     <o2.1> interrupt enable
//     <o3.1> generate interrupt
//     <o4.1> generate event
//     <o5.1> use rising trigger for interrupt/event
//     <o6.1> use falling trigger for interrupt/event
//     <o7.4..7> use pin for for interrupt/event
//        <i> Default: pin = PA1
//          <0=>         pin = PA1
//          <1=>         pin = PB1
//          <2=>         pin = PC1
//          <3=>         pin = PD1
//          <4=>         pin = PE1
//          <5=>         pin = PF1
//          <6=>         pin = PG2
//   </e>

//--------------------------------------------------------------------------- EXTI line 2
//   <e1.2> EXTI2: EXTI line 2 enable
//     <o2.2> interrupt enable
//     <o3.2> generate interrupt
//     <o4.2> generate event
//     <o5.2> use rising trigger for interrupt/event
//     <o6.2> use falling trigger for interrupt/event
//     <o7.8..11> use pin for for interrupt/event
//        <i> Default: pin = PA2
//          <0=>         pin = PA2
//          <1=>         pin = PB2
//          <2=>         pin = PC2
//          <3=>         pin = PD2
//          <4=>         pin = PE2
//          <5=>         pin = PF2
//          <6=>         pin = PG2
//   </e>

//--------------------------------------------------------------------------- EXTI line 3
//   <e1.3> EXTI3: EXTI line 3 enable
//     <o2.3> interrupt enable
//     <o3.3> generate interrupt
//     <o4.3> generate event
//     <o5.3> use rising trigger for interrupt/event
//     <o6.3> use falling trigger for interrupt/event
//     <o7.12..15> use pin for for interrupt/event
//        <i> Default: pin = PA3
//          <0=>         pin = PA3
//          <1=>         pin = PB3
//          <2=>         pin = PC3
//          <3=>         pin = PD3
//          <4=>         pin = PE3
//          <5=>         pin = PF3
//          <6=>         pin = PG3
//   </e>

//--------------------------------------------------------------------------- EXTI line 4
//   <e1.4> EXTI4: EXTI line 4 enable
//     <o2.4> interrupt enable
//     <o3.4> generate interrupt
//     <o4.4> generate event
//     <o5.4> use rising trigger for interrupt/event
//     <o6.4> use falling trigger for interrupt/event
//     <o8.0..3> use pin for for interrupt/event
//        <i> Default: pin = PA4
//          <0=>         pin = PA4
//          <1=>         pin = PB4
//          <2=>         pin = PC4
//          <3=>         pin = PD4
//          <4=>         pin = PE4
//          <5=>         pin = PF4
//          <6=>         pin = PG4
//   </e>

//--------------------------------------------------------------------------- EXTI line 5
//   <e1.5> EXTI5: EXTI line 5 enable
//     <o2.5> interrupt enable
//     <o3.5> generate interrupt
//     <o4.5> generate event
//     <o5.5> use rising trigger for interrupt/event
//     <o6.5> use falling trigger for interrupt/event
//     <o8.4..7> use pin for for interrupt/event
//        <i> Default: pin = PA5
//          <0=>         pin = PA5
//          <1=>         pin = PB5
//          <2=>         pin = PC5
//          <3=>         pin = PD5
//          <4=>         pin = PE5
//          <5=>         pin = PF5
//          <6=>         pin = PG5
//   </e>

//--------------------------------------------------------------------------- EXTI line 6
//   <e1.6> EXTI6: EXTI line 6 enable
//     <o2.6> interrupt enable
//     <o3.6> generate interrupt
//     <o4.6> generate event
//     <o5.6> use rising trigger for interrupt/event
//     <o6.6> use falling trigger for interrupt/event
//     <o8.8..11> use pin for for interrupt/event
//        <i> Default: pin = PA6
//          <0=>         pin = PA6
//          <1=>         pin = PB6
//          <2=>         pin = PC6
//          <3=>         pin = PD6
//          <4=>         pin = PE6
//          <5=>         pin = PF6
//          <6=>         pin = PG6
//   </e>

//--------------------------------------------------------------------------- EXTI line 7
//   <e1.7> EXTI7: EXTI line 7 enable
//     <o2.7> interrupt enable
//     <o3.7> generate interrupt
//     <o4.7> generate event
//     <o5.7> use rising trigger for interrupt/event
//     <o6.7> use falling trigger for interrupt/event
//     <o8.12..15> use pin for for interrupt/event
//        <i> Default: pin = PA7
//          <0=>         pin = PA7
//          <1=>         pin = PB7
//          <2=>         pin = PC7
//          <3=>         pin = PD7
//          <4=>         pin = PE7
//          <5=>         pin = PF7
//          <6=>         pin = PG7
//   </e>

//--------------------------------------------------------------------------- EXTI line 8
//   <e1.8> EXTI8: EXTI line 8 enable
//     <o2.8> interrupt enable
//     <o3.8> generate interrupt
//     <o4.8> generate event
//     <o5.8> use rising trigger for interrupt/event
//     <o6.8> use falling trigger for interrupt/event
//     <o9.0..3> use pin for for interrupt/event
//        <i> Default: pin = PA8
//          <0=>         pin = PA8
//          <1=>         pin = PB8
//          <2=>         pin = PC8
//          <3=>         pin = PD8
//          <4=>         pin = PE8
//          <5=>         pin = PF8
//          <6=>         pin = PG8
//   </e>

//--------------------------------------------------------------------------- EXTI line 9
//   <e1.9> EXTI9: EXTI line 9 enable
//     <o2.9> interrupt enable
//     <o3.9> generate interrupt
//     <o4.9> generate event
//     <o5.9> use rising trigger for interrupt/event
//     <o6.9> use falling trigger for interrupt/event
//     <o9.4..7> use pin for for interrupt/event
//        <i> Default: pin = PA9
//          <0=>         pin = PA9
//          <1=>         pin = PB9
//          <2=>         pin = PC9
//          <3=>         pin = PD9
//          <4=>         pin = PE9
//          <5=>         pin = PF9
//          <6=>         pin = PG9
//   </e>

//--------------------------------------------------------------------------- EXTI line 10
//   <e1.10> EXTI10: EXTI line 10 enable
//     <o2.10> interrupt enable
//     <o3.10> generate interrupt
//     <o4.10> generate event
//     <o5.10> use rising trigger for interrupt/event
//     <o6.10> use falling trigger for interrupt/event
//     <o9.8..11> use pin for for interrupt/event
//        <i> Default: pin = PA10
//          <0=>         pin = PA10
//          <1=>         pin = PB10
//          <2=>         pin = PC10
//          <3=>         pin = PD10
//          <4=>         pin = PE10
//          <5=>         pin = PF10
//          <6=>         pin = PG10
//   </e>

//--------------------------------------------------------------------------- EXTI line 11
//   <e1.11> EXTI11: EXTI line 11 enable
//     <o2.11> interrupt enable
//     <o3.11> generate interrupt
//     <o4.11> generate event
//     <o5.11> use rising trigger for interrupt/event
//     <o6.11> use falling trigger for interrupt/event
//     <o9.12..15> use pin for for interrupt/event
//        <i> Default: pin = PA11
//          <0=>         pin = PA11
//          <1=>         pin = PB11
//          <2=>         pin = PC11
//          <3=>         pin = PD11
//          <4=>         pin = PE11
//          <5=>         pin = PF11
//          <6=>         pin = PG11
//   </e>

//--------------------------------------------------------------------------- EXTI line 12
//   <e1.12> EXTI12: EXTI line 12 enable
//     <o2.12> interrupt enable
//     <o3.12> generate interrupt
//     <o4.12> generate event
//     <o5.12> use rising trigger for interrupt/event
//     <o6.12> use falling trigger for interrupt/event
//     <o10.0..3> use pin for for interrupt/event
//        <i> Default: pin = PA12
//          <0=>         pin = PA12
//          <1=>         pin = PB12
//          <2=>         pin = PC12
//          <3=>         pin = PD12
//          <4=>         pin = PE12
//          <5=>         pin = PF12
//          <6=>         pin = PG12
//   </e>

//--------------------------------------------------------------------------- EXTI line 13
//   <e1.13> EXTI13: EXTI line 13 enable
//     <o2.13> interrupt enable
//     <o3.13> generate interrupt
//     <o4.13> generate event
//     <o5.13> use rising trigger for interrupt/event
//     <o6.13> use falling trigger for interrupt/event
//     <o10.4..7> use pin for for interrupt/event
//        <i> Default: pin = PA13
//          <0=>         pin = PA13
//          <1=>         pin = PB13
//          <2=>         pin = PC13
//          <3=>         pin = PD13
//          <4=>         pin = PE13
//          <5=>         pin = PF13
//          <6=>         pin = PG13
//   </e>

//--------------------------------------------------------------------------- EXTI line 14
//   <e1.14> EXTI14: EXTI line 14 enable
//     <o2.14> interrupt enable
//     <o3.14> generate interrupt
//     <o4.14> generate event
//     <o5.14> use rising trigger for interrupt/event
//     <o6.14> use falling trigger for interrupt/event
//     <o10.8..11> use pin for for interrupt/event
//        <i> Default: pin = PA14
//          <0=>         pin = PA14
//          <1=>         pin = PB14
//          <2=>         pin = PC14
//          <3=>         pin = PD14
//          <4=>         pin = PE14
//          <5=>         pin = PF14
//          <6=>         pin = PG14
//   </e>

//--------------------------------------------------------------------------- EXTI line 15
//   <e1.15> EXTI15: EXTI line 15 enable
//     <o2.15> interrupt enable
//     <o3.15> generate interrupt
//     <o4.15> generate event
//     <o5.15> use rising trigger for interrupt/event
//     <o6.15> use falling trigger for interrupt/event
//     <o10.12..15> use pin for for interrupt/event
//        <i> Default: pin = PA15
//          <0=>         pin = PA15
//          <1=>         pin = PB15
//          <2=>         pin = PC15
//          <3=>         pin = PD15
//          <4=>         pin = PE15
//          <5=>         pin = PF15
//          <6=>         pin = PG15
//   </e>

// </e> End of External interrupt/event Configuration
#define __EXTI_SETUP              0                       //  0
#define __EXTI_USED               0x0000                  //  1
#define __EXTI_INTERRUPTS         0x00000000              //  2
#define __EXTI_IMR                0x00000000              //  3
#define __EXTI_EMR                0x00000000              //  4
#define __EXTI_RTSR               0x00000000              //  5
#define __EXTI_FTSR               0x00000000              //  6
#define __AFIO_EXTICR1            0x00000000              //  7
#define __AFIO_EXTICR2            0x00000000              //  8
#define __AFIO_EXTICR3            0x00000000              //  9
#define __AFIO_EXTICR4            0x00000000              // 10


//=========================================================================== Alternate Function remap Configuration
// <e0> Alternate Function remap Configuration
//--------------------------------------------------------------------------- SPI1 remapping
//   <o1.0> SPI1 remapping
//      <i> Default: No Remap (NSS/PA4, SCK/PA5, MISO/PA6, MOSI/PA7)
//        <0=>         No Remap (NSS/PA4, SCK/PA5, MISO/PA6, MOSI/PA7)
//        <1=>         Remap (NSS/PA15, SCK/PB3, MISO/PB4, MOSI/PB5)

//--------------------------------------------------------------------------- I2C1 remapping
//   <o1.1> I2C1 remapping
//      <i> Default: No Remap (SCL/PB6, SDA/PB7)
//        <0=>         No Remap (SCL/PB6, SDA/PB7)
//        <1=>         Remap (SCL/PB8, SDA/PB9)

//--------------------------------------------------------------------------- USART1 remapping
//   <O1.2> USART1 remapping
//      <i> Default: No Remap (TX/PA9, RX/PA10)
//        <0=>         No Remap (TX/PA9, RX/PA10)
//        <1=>         Remap (TX/PB6, RX/PB7)

//--------------------------------------------------------------------------- USART2 remapping
//   <o1.3> USART2 remapping
//      <i> Default: No Remap (CTS/PA0, RTS/PA1, TX/PA2, RX/PA3, CK/PA4)
//        <0=>         No Remap (CTS/PA0, RTS/PA1, TX/PA2, RX/PA3, CK/PA4)
//        <1=>         Remap (CTS/PD3, RTS/PD4, TX/PD5, RX/PD6, CK/PD7)

//--------------------------------------------------------------------------- USART3 remapping
//   <o1.4..5> USART3 remapping
//      <i> Default: No Remap (TX/PB10, RX/PB11, CK/PB12, CTS/PB13, RTS/PB14)
//        <0=>         No Remap (TX/PB10, RX/PB11, CK/PB12, CTS/PB13, RTS/PB14)
//        <1=>         Partial Remap (TX/PC10, RX/PC11, CK/PC12, CTS/PB13, RTS/PB14)
//        <3=>         Full Remap (TX/PD8, RX/PD9, CK/PD10, CTS/PD11, RTS/PD12)

//--------------------------------------------------------------------------- TIM1 remapping
//   <o1.6..7> TIM1 remapping
//      <i> Default: No Remap (ETR/PA12, CH1/PA8, CH2/PA9, CH3/PA10, CH4/PA11, BKIN/PB12, CH1N/PB13, CH2N/PB14, CH3N/PB15)
//        <0=>         No Remap (ETR/PA12, CH1/PA8, CH2/PA9, CH3/PA10, CH4/PA11, BKIN/PB12, CH1N/PB13, CH2N/PB14, CH3N/PB15)
//        <1=>         Partial Remap (ETR/PA12, CH1/PA8, CH2/PA9, CH3/PA10, CH4/PA11, BKIN/PA6, CH1N/PA7, CH2N/PB0, CH3N/PB1)
//        <3=>         Full Remap (ETR/PE7, CH1/PE9, CH2/PE11, CH3/PE13, CH4/PE14, BKIN/PE15, CH1N/PE8, CH2N/PE10, CH3N/PE12)

//--------------------------------------------------------------------------- TIM2 remapping
//   <o1.8..9> TIM2 remapping
//      <i> Default: No Remap (CH1/ETR/PA0, CH2/PA1, CH3/PA2, CH4/PA3)
//        <0=>         No Remap (CH1/ETR/PA0, CH2/PA1, CH3/PA2, CH4/PA3)
//        <1=>         Partial Remap (CH1/ETR/PA15, CH2/PB3, CH3/PA2, CH4/PA3)
//        <2=>         Partial Remap (CH1/ETR/PA0, CH2/PA1, CH3/PB10, CH4/PB11)
//        <3=>         Full Remap (CH1/ETR/PA15, CH2/PB3, CH3/PB10, CH4/PB11)

//--------------------------------------------------------------------------- TIM3 remapping
//   <o1.10..11> TIM3 remapping
//      <i> Default: No Remap (CH1/PA6, CH2/PA7, CH3/PB0, CH4/PB1)
//        <0=>         No Remap (CH1/PA6, CH2/PA7, CH3/PB0, CH4/PB1)
//        <2=>         Partial Remap (CH1/PB4, CH2/PB5, CH3/PB0, CH4/PB1)
//        <3=>         Full Remap (CH1/PC6, CH2/PC7, CH3/PC8, CH4/PC9)

//--------------------------------------------------------------------------- TIM4 remapping
//   <o1.12> TIM4 remapping
//      <i> Default: No Remap (CH1/PB6, CH2/PB7, CH3/PB8, CH4/PB9)
//        <0=>         No Remap (CH1/PB6, CH2/PB7, CH3/PB8, CH4/PB9)
//        <1=>         Remap (CH1/PD12, CH2/PD13, CH3/PD14, CH4/PD15)

//--------------------------------------------------------------------------- CAN remapping
//   <o1.13..14> CAN remapping
//      <i> Default: No Remap (CANRX/PA11, CANTX/PA12)
//        <0=>         No Remap (CANRX/PA11, CANTX/PA12)
//        <2=>         Remap (CANRX/PB8, CANTX/PB9)
//        <3=>         Remap (CANRX/PD0, CANTX/PPD1)

//--------------------------------------------------------------------------- PD01 remapping
//   <o1.15> PD01 remapping
//      <i> Default: No Remap
//        <0=>         No Remap
//        <1=>         Remap (PD0/OSCIN, PD1/OSC_OUT)

// </e> End of Alternate Function remap Configuration
#define __AFREMAP_SETUP           0                       //  0
#define __AFIO_MAPR               0x00000000              //  1


//=========================================================================== General purpose I/O Configuration
// <e0> General purpose I/O Configuration
//--------------------------------------------------------------------------- GPIO port A
//   <e1.0> GPIOA : GPIO port A used
//     <o2.0..3>   Pin 0 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o2.4..7>   Pin 1 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o2.8..11>  Pin 2 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o2.12..15> Pin 3 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o2.16..19> Pin 4 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o2.20..23> Pin 5 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o2.24..27> Pin 6 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o2.28..31> Pin 7 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o3.0..3>   Pin 8 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o3.4..7>   Pin 9 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o3.8..11>  Pin 10 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o3.12..15> Pin 11 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o3.16..19> Pin 12 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o3.20..23> Pin 13 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o3.24..27> Pin 14 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o3.28..31> Pin 15 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//   </e>

//--------------------------------------------------------------------------- GPIO port B
//   <e1.1> GPIOB : GPIO port B used
//     <o4.0..3>   Pin 0 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o4.4..7>   Pin 1 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o4.8..11>  Pin 2 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o4.12..15> Pin 3 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o4.16..19> Pin 4 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o4.20..23> Pin 5 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o4.24..27> Pin 6 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o4.28..31> Pin 7 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o5.0..3>   Pin 8 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o5.4..7>   Pin 9 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o5.8..11>  Pin 10 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o5.12..15> Pin 11 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o5.16..19> Pin 12 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o5.20..23> Pin 13 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o5.24..27> Pin 14 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o5.28..31> Pin 15 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//   </e>

//--------------------------------------------------------------------------- GPIO port C
//   <e1.2> GPIOC : GPIO port C used
//     <o6.0..3>   Pin 0 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o6.4..7>   Pin 1 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o6.8..11>  Pin 2 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o6.12..15> Pin 3 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o6.16..19> Pin 4 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o6.20..23> Pin 5 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o6.24..27> Pin 6 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o6.28..31> Pin 7 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o7.0..3>   Pin 8 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o7.4..7>   Pin 9 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o7.8..11>  Pin 10 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o7.12..15> Pin 11 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o7.16..19> Pin 12 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o7.20..23> Pin 13 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o7.24..27> Pin 14 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o7.28..31> Pin 15 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//   </e>

//--------------------------------------------------------------------------- GPIO port D
//   <e1.3> GPIOD : GPIO port D used
//     <o8.0..3>   Pin 0 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o8.4..7>   Pin 1 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o8.8..11>  Pin 2 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o8.12..15> Pin 3 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o8.16..19> Pin 4 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o8.20..23> Pin 5 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o8.24..27> Pin 6 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o8.28..31> Pin 7 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o9.0..3>   Pin 8 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o9.4..7>   Pin 9 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o9.8..11>  Pin 10 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o9.12..15> Pin 11 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o9.16..19> Pin 12 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o9.20..23> Pin 13 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o9.24..27> Pin 14 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o9.28..31> Pin 15 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//   </e>

//--------------------------------------------------------------------------- GPIO port E
//   <e1.4> GPIOE : GPIO port E used
//     <o10.0..3>   Pin 0 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o10.4..7>   Pin 1 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o10.8..11>  Pin 2 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o10.12..15> Pin 3 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o10.16..19> Pin 4 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o10.20..23> Pin 5 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o10.24..27> Pin 6 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o10.28..31> Pin 7 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o11.0..3>   Pin 8 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o11.4..7>   Pin 9 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o11.8..11>  Pin 10 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o11.12..15> Pin 11 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o11.16..19> Pin 12 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o11.20..23> Pin 13 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o11.24..27> Pin 14 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o11.28..31> Pin 15 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//   </e1.4>

//--------------------------------------------------------------------------- GPIO port F
//   <e1.5> GPIOF : GPIO port F used
//     <o12.0..3>   Pin 0 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o12.4..7>   Pin 1 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o12.8..11>  Pin 2 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o12.12..15> Pin 3 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o12.16..19> Pin 4 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o12.20..23> Pin 5 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o12.24..27> Pin 6 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o12.28..31> Pin 7 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o13.0..3>   Pin 8 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o13.4..7>   Pin 9 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o13.8..11>  Pin 10 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o13.12..15> Pin 11 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o13.16..19> Pin 12 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o13.20..23> Pin 13 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o13.24..27> Pin 14 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o13.28..31> Pin 15 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//   </e1.5>

//--------------------------------------------------------------------------- GPIO port G
//   <e1.6> GPIOG : GPIO port G used
//     <o14.0..3>   Pin 0 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o14.4..7>   Pin 1 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o14.8..11>  Pin 2 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o14.12..15> Pin 3 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o14.16..19> Pin 4 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o14.20..23> Pin 5 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o14.24..27> Pin 6 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o14.28..31> Pin 7 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o15.0..3>   Pin 8 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o15.4..7>   Pin 9 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o15.8..11>  Pin 10 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o15.12..15> Pin 11 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o15.16..19> Pin 12 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o15.20..23> Pin 13 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o15.24..27> Pin 14 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//     <o15.28..31> Pin 15 used as 
//                 <0=>Analog Input
//                 <4=>Floating Input
//                 <8=>Input with pull-up / pull-down
//                 <1=>General Purpose Output push-pull (max speed 10MHz)
//                 <5=>General Purpose Output open-drain (max speed 10MHz)
//                 <2=>General Purpose Output push-pull (max speed  2MHz)
//                 <6=>General Purpose Output open-drain (max speed  2MHz)
//                 <3=>General Purpose Output push-pull (max speed 50MHz)
//                 <7=>General Purpose Output open-drain (max speed 50MHz)
//                 <9=>Alternate Function push-pull (max speed 10MHz)
//                 <13=>Alternate Function open-drain (max speed 10MHz)
//                 <10=>Alternate Function push-pull (max speed  2MHz)
//                 <14=>Alternate Function open-drain (max speed  2MHz)
//                 <11=>Alternate Function push-pull (max speed 50MHz)
//                 <15=>Alternate Function open-drain (max speed 50MHz)
//   </e1.6>
// </e> End of General purpose I/O Configuration
#define __GPIO_SETUP              1
#define __GPIO_USED               0x07
#define __GPIOA_CRL               0x00000004
#define __GPIOA_CRH               0x00000000
#define __GPIOB_CRL               0x00000000
#define __GPIOB_CRH               0x33333333
#define __GPIOC_CRL               0x00000000
#define __GPIOC_CRH               0x00400000
#define __GPIOD_CRL               0x00000000
#define __GPIOD_CRH               0x00000000
#define __GPIOE_CRL               0x00000000
#define __GPIOE_CRH               0x00000000
#define __GPIOF_CRL               0x00000000
#define __GPIOF_CRH               0x00000000
#define __GPIOG_CRL               0x00000000
#define __GPIOG_CRH               0x00000000


//=========================================================================== Embedded Flash Configuration
// <e0> Embedded Flash Configuration
//   <h> Flash Access Control Configuration (FLASH_ACR)
//     <o1.0..2> LATENCY: Latency
//       <i> Default: 2 wait states
//                     <0=> 0 wait states
//                     <1=> 1 wait states
//                     <2=> 2 wait states
//     <o1.3> HLFCYA: Flash Half Cycle Access Enable
//     <o1.4> PRFTBE: Prefetch Buffer Enable
//     <o1.5> PRFTBS: Prefetch Buffer Status Enable
//   </h>
// </e>
#define __EFI_SETUP               1
#define __EFI_ACR_Val             0x00000012



/*----------------------------------------------------------------------------
  DEFINES
 *----------------------------------------------------------------------------*/
#define CFGR_SWS_MASK       0x0000000C             // Mask for used SYSCLK
#define CFGR_SW_MASK        0x00000003             // Mask for used SYSCLK
#define CFGR_PLLMULL_MASK   0x003C0000             // Mask for PLL multiplier
#define CFGR_PLLXTPRE_MASK  0x00020000             // Mask for PLL HSE devider
#define CFGR_PLLSRC_MASK    0x00010000             // Mask for PLL clock source
#define CFGR_HPRE_MASK      0x000000F0             // Mask for AHB prescaler
#define CFGR_PRE1_MASK      0x00000700             // Mask for APB1 prescaler     
#define CFGR_PRE2_MASK      0x00003800             // Mask for APB2 prescaler 
    
/*----------------------------------------------------------------------------
 Define SYSCLK
 *----------------------------------------------------------------------------*/
#define __HSI 8000000UL
//#define __HSE 8000000UL
#define __PLLMULL (((__RCC_CFGR_VAL & CFGR_PLLMULL_MASK) >> 18) + 2)

#if   ((__RCC_CFGR_VAL & CFGR_SW_MASK) == 0x00) 
  #define __SYSCLK   __HSI                        // HSI is used as system clock
#elif ((__RCC_CFGR_VAL & CFGR_SW_MASK) == 0x01)
  #define __SYSCLK   __HSE                        // HSE is used as system clock
#elif ((__RCC_CFGR_VAL & CFGR_SW_MASK) == 0x02)
  #if (__RCC_CFGR_VAL & CFGR_PLLSRC_MASK)         // HSE is PLL clock source
    #if (__RCC_CFGR_VAL & CFGR_PLLXTPRE_MASK)     // HSE/2 is used
      #define __SYSCLK  ((__HSE >> 1) * __PLLMULL)// SYSCLK = HSE/2 * pllmull
    #else                                         // HSE is used
      #define __SYSCLK  ((__HSE >> 0) * __PLLMULL)// SYSCLK = HSE   * pllmul
    #endif  
  #else                                           // HSI/2 is PLL clock source
    #define __SYSCLK  ((__HSI >> 1) * __PLLMULL)  // SYSCLK = HSI/2 * pllmul
  #endif
#else
   #error "ask for help"
#endif
   
/*----------------------------------------------------------------------------
 Define  HCLK
 *----------------------------------------------------------------------------*/
#define __HCLKPRESC  ((__RCC_CFGR_VAL & CFGR_HPRE_MASK) >> 4)
#if (__HCLKPRESC & 0x08)
  #define __HCLK        (__SYSCLK >> ((__HCLKPRESC & 0x07)+1))
#else
  #define __HCLK        (__SYSCLK)
#endif

/*----------------------------------------------------------------------------
 Define  PCLK1
 *----------------------------------------------------------------------------*/
#define __PCLK1PRESC  ((__RCC_CFGR_VAL & CFGR_PRE1_MASK) >> 8)
#if (__PCLK1PRESC & 0x04)
  #define __PCLK1       (__HCLK >> ((__PCLK1PRESC & 0x03)+1))
#else
  #define __PCLK1       (__HCLK)
#endif

/*----------------------------------------------------------------------------
 Define  PCLK2
 *----------------------------------------------------------------------------*/
#define __PCLK2PRESC  ((__RCC_CFGR_VAL & CFGR_PRE2_MASK) >> 11)
#if (__PCLK2PRESC & 0x04)
  #define __PCLK2       (__HCLK >> ((__PCLK2PRESC & 0x03)+1))
#else
  #define __PCLK2       (__HCLK)
#endif


/*----------------------------------------------------------------------------
 Define  IWDG PR and RLR settings
 *----------------------------------------------------------------------------*/
#if   (__IWDG_PERIOD >  16384000UL)
  #define __IWDG_PR             (6)
  #define __IWDGCLOCK (32000UL/256)
#elif (__IWDG_PERIOD >   8192000UL)
  #define __IWDG_PR             (5)
  #define __IWDGCLOCK (32000UL/128)
#elif (__IWDG_PERIOD >   4096000UL)
  #define __IWDG_PR             (4)
  #define __IWDGCLOCK  (32000UL/64)
#elif (__IWDG_PERIOD >   2048000UL)
  #define __IWDG_PR             (3)
  #define __IWDGCLOCK  (32000UL/32)
#elif (__IWDG_PERIOD >   1024000UL)
  #define __IWDG_PR             (2)
  #define __IWDGCLOCK  (32000UL/16)
#elif (__IWDG_PERIOD >    512000UL)
  #define __IWDG_PR             (1)
  #define __IWDGCLOCK   (32000UL/8)
#else
  #define __IWDG_PR             (0)
  #define __IWDGCLOCK   (32000UL/4)
#endif
#define __IWGDCLK  (32000UL/(0x04<<__IWDG_PR))
#define __IWDG_RLR (__IWDG_PERIOD*__IWGDCLK/1000000UL-1)


/*----------------------------------------------------------------------------
 Define  SYSTICKCLK
 *----------------------------------------------------------------------------*/
#if (__SYSTICK_CTRL_VAL & 0x04)
  #define __SYSTICKCLK    (__HCLK)
#else
  #define __SYSTICKCLK    (__HCLK/8)
#endif


/*----------------------------------------------------------------------------
 Define  RTCCLK
 *----------------------------------------------------------------------------*/
#if   ((__RTC_CLKSRC_VAL & 0x00000300) == 0x00000000)
  #define __RTCCLK        (0)
#elif ((__RTC_CLKSRC_VAL & 0x00000300) == 0x00000100)
  #define __RTCCLK        (32768)
#elif ((__RTC_CLKSRC_VAL & 0x00000300) == 0x00000200)
  #define __RTCCLK        (32000)
#elif ((__RTC_CLKSRC_VAL & 0x00000300) == 0x00000300)
  #define __RTCCLK        (__HSE/128)
#endif


/*----------------------------------------------------------------------------
 Define  TIM1CLK
 *----------------------------------------------------------------------------*/
#if (__PCLK2PRESC & 0x04)
  #define __TIM1CLK     (2*__PCLK2)
#else
  #define __TIM1CLK     (__PCLK2)
#endif


/*----------------------------------------------------------------------------
 Define  TIMXCLK
 *----------------------------------------------------------------------------*/
#if (__PCLK1PRESC & 0x04)
  #define __TIMXCLK    (2*__PCLK1)
#else
  #define __TIMXCLK    (__PCLK1)
#endif


/*----------------------------------------------------------------------------
 Define Real Time Clock CNT and ALR settings
 *----------------------------------------------------------------------------*/
#define __RTC_CNT_TICKS  ((__RTC_TIME_H *3600UL)+(__RTC_TIME_M *60UL)+(__RTC_TIME_S) )
#define __RTC_ALR_TICKS  ((__RTC_ALARM_H*3600UL)+(__RTC_ALARM_M*60UL)+(__RTC_ALARM_S))
#define __RTC_CNT        (__RTC_CNT_TICKS*1000UL/__RTC_PERIOD)
#define __RTC_ALR        (__RTC_ALR_TICKS*1000UL/__RTC_PERIOD)

/*----------------------------------------------------------------------------
 Define Timer PSC and ARR settings
 *----------------------------------------------------------------------------*/
#define __VAL(__TIMCLK, __PERIOD) ((__TIMCLK/1000000UL)*__PERIOD)
//#define __PSC(__TIMCLK, __PERIOD) ((__VAL(__TIMCLK, __PERIOD)-1)>>15)
#define __PSC(__TIMCLK, __PERIOD)  (((__VAL(__TIMCLK, __PERIOD)+49999UL)/50000UL) - 1)
#define __ARR(__TIMCLK, __PERIOD) ((__VAL(__TIMCLK, __PERIOD)/(__PSC(__TIMCLK, __PERIOD)+1)) - 1)


/*----------------------------------------------------------------------------
 Define  Baudrate setting (BRR) for USART1 
 *----------------------------------------------------------------------------*/
#define __DIV(__PCLK, __BAUD)       ((__PCLK*25)/(4*__BAUD))
#define __DIVMANT(__PCLK, __BAUD)   (__DIV(__PCLK, __BAUD)/100)
#define __DIVFRAQ(__PCLK, __BAUD)   (((__DIV(__PCLK, __BAUD) - (__DIVMANT(__PCLK, __BAUD) * 100)) * 16 + 50) / 100)
#define __USART_BRR(__PCLK, __BAUD) ((__DIVMANT(__PCLK, __BAUD) << 4)|(__DIVFRAQ(__PCLK, __BAUD) & 0x0F))


#if __EFI_SETUP
/*----------------------------------------------------------------------------
 STM32 embedded Flash interface setup.
 initializes the ACR register
 *----------------------------------------------------------------------------*/
__inline static void stm32_EfiSetup (void) {

  FLASH->ACR = __EFI_ACR_Val;                        // set access control register 
}
#endif


#if __CLOCK_SETUP
/*----------------------------------------------------------------------------
 STM32 clock setup.
 initializes the RCC register
 *----------------------------------------------------------------------------*/
__inline static void stm32_ClockSetup (void) {
  /* Clock Configuration*/

  RCC->CFGR = __RCC_CFGR_VAL;                        // set clock configuration register
  RCC->CR   = __RCC_CR_VAL;                          // set clock control register

  if (__RCC_CR_VAL & RCC_CR_HSION) {                 // if HSI enabled
    while ((RCC->CR & RCC_CR_HSIRDY) == 0);          // Wait for HSIRDY = 1 (HSI is ready)
  }

  if (__RCC_CR_VAL & RCC_CR_HSEON) {                 // if HSE enabled
    while ((RCC->CR & RCC_CR_HSERDY) == 0);          // Wait for HSERDY = 1 (HSE is ready)
  }

  if (__RCC_CR_VAL & RCC_CR_PLLON) {                 // if PLL enabled
    while ((RCC->CR & RCC_CR_PLLRDY) == 0);          // Wait for PLLRDY = 1 (PLL is ready)
  }

  /* Wait till SYSCLK is stabilized (depending on selected clock) */
  while ((RCC->CFGR & RCC_CFGR_SWS) != ((__RCC_CFGR_VAL<<2) & RCC_CFGR_SWS));
} // end of stm32_ClockSetup
#endif


#if __NVIC_SETUP
/*----------------------------------------------------------------------------
 STM32 NVIC setup.
 initializes the NVIC register
 *----------------------------------------------------------------------------*/
__inline static void stm32_NvicSetup (void) {

  if (__NVIC_USED & (1 << 0)) {                              // Vector Table Offset Register
    SCB->VTOR = (__NVIC_VTOR_VAL & (u32)0x3FFFFF80);         // set register
  }

} // end of stm32_NvicSetup
#endif


#if __IWDG_SETUP
/*----------------------------------------------------------------------------
 STM32 Independent watchdog setup.
 initializes the IWDG register
 *----------------------------------------------------------------------------*/
__inline static void stm32_IwdgSetup (void) {

//  RCC->CSR |= (1<<0);                                           // LSI enable, necessary for IWDG
//  while ((RCC->CSR & (1<<1)) == 0);                             // wait till LSI is ready

  IWDG->KR  = 0x5555;                                           // enable write to PR, RLR
  IWDG->PR  = __IWDG_PR;                                        // Init prescaler
  IWDG->RLR = __IWDG_RLR;                                       // Init RLR
  IWDG->KR  = 0xAAAA;                                           // Reload the watchdog
  IWDG->KR  = 0xCCCC;                                           // Start the watchdog
} // end of stm32_IwdgSetup
#endif


#if __SYSTICK_SETUP
/*----------------------------------------------------------------------------
 STM32 System Timer setup.
 initializes the SysTick register
 *----------------------------------------------------------------------------*/
__inline static void stm32_SysTickSetup (void) {

#if ((__SYSTICK_PERIOD*(__SYSTICKCLK/1000)-1) > 0xFFFFFF)       // reload value to large
   #error "Reload Value to large! Please use 'HCLK/8' as System Timer clock source or smaller period"
#else
  SysTick->LOAD  = __SYSTICK_PERIOD*(__SYSTICKCLK/1000)-1;      // set reload register
  SysTick->CTRL  = __SYSTICK_CTRL_VAL;                          // set clock source and Interrupt enable

  SysTick->VAL   =  0;                                          // clear  the counter
  SysTick->CTRL |= SYSTICK_CSR_ENABLE;                          // enable the counter
#endif
} // end of stm32_SysTickSetup
#endif


#if __RTC_SETUP
/*----------------------------------------------------------------------------
 STM32 Real Time Clock setup.
 initializes the RTC Prescaler and RTC counter register
 *----------------------------------------------------------------------------*/
__inline static void stm32_RtcSetup (void) {

  RCC->APB1ENR |= RCC_APB1ENR_PWREN;                            // enable clock for Power interface
  PWR->CR      |= PWR_CR_DBP;                                   // enable access to RTC, BDC registers

  if ((__RTC_CLKSRC_VAL & RCC_BDCR_RTCSEL) == 0x00000100) {     // LSE is RTC clock source
    RCC->BDCR |= RCC_BDCR_LSEON;                                // enable LSE
    while ((RCC->BDCR & RCC_BDCR_LSERDY) == 0);                 // Wait for LSERDY = 1 (LSE is ready)
  }

  if ((__RTC_CLKSRC_VAL & RCC_BDCR_RTCSEL) == 0x00000200) {     // LSI is RTC clock source
    RCC->CSR |= RCC_CSR_LSION;                                  // enable LSI
    while ((RCC->CSR & RCC_CSR_LSIRDY) == 0);                   // Wait for LSERDY = 1 (LSE is ready)
  }

  RCC->BDCR |= (__RTC_CLKSRC_VAL | RCC_BDCR_RTCEN);             // set RTC clock source, enable RTC clock

//  RTC->CRL   &= ~(1<<3);                                        // reset Registers Synchronized Flag
//  while ((RTC->CRL & (1<<3)) == 0);                             // wait until registers are synchronized

  RTC->CRL  |=  RTC_CRL_CNF;                                    // set configuration mode
  RTC->PRLH  = ((__RTC_PERIOD*__RTCCLK/1000-1)>>16) & 0x00FF;   // set prescaler load register high
  RTC->PRLL  = ((__RTC_PERIOD*__RTCCLK/1000-1)    ) & 0xFFFF;   // set prescaler load register low
  RTC->CNTH  = ((__RTC_CNT)>>16) & 0xFFFF;                      // set counter high
  RTC->CNTL  = ((__RTC_CNT)    ) & 0xFFFF;                      // set counter low
  RTC->ALRH  = ((__RTC_ALR)>>16) & 0xFFFF;                      // set alarm high
  RTC->ALRL  = ((__RTC_ALR)    ) & 0xFFFF;                      // set alarm low
  if (__RTC_INTERRUPTS) {                                       // RTC interrupts used
    RTC->CRH = __RTC_CRH;                                       // enable RTC interrupts
    NVIC->ISER[0] |= (1 << (RTC_IRQChannel & 0x1F));            // enable interrupt
  }
  RTC->CRL  &= ~RTC_CRL_CNF;                                    // reset configuration mode
  while ((RTC->CRL & RTC_CRL_RTOFF) == 0);                      // wait until write is finished

  PWR->CR   &= ~PWR_CR_DBP;                                     // disable access to RTC registers
} // end of stm32_RtcSetup
#endif


#if __TIMER_SETUP
/*----------------------------------------------------------------------------
 STM32 Timer setup.
 initializes the Timer register
 *----------------------------------------------------------------------------*/
__inline static void stm32_TimerSetup (void) {
  
  if (__TIMER_USED & 0x01) {                                // TIM1 used
    RCC->APB2ENR |= RCC_APB2ENR_TIM1EN;                     // enable clock for TIM1

    TIM1->PSC = __PSC(__TIM1CLK, __TIM1_PERIOD);            // set prescaler
    TIM1->ARR = __ARR(__TIM1CLK, __TIM1_PERIOD);            // set auto-reload
    TIM1->RCR = __TIM1_RCR;                                 // set repetition counter

    TIM1->CR1 = 0;                                          // reset command register 1
    TIM1->CR2 = 0;                                          // reset command register 2

    if (__TIMER_DETAILS & 0x01) {                           // detailed settings used
      TIM1->PSC = __TIM1_PSC;                               // set prescaler
      TIM1->ARR = __TIM1_ARR;                               // set auto-reload

      TIM1->CCR1  = __TIM1_CCR1;                            //
      TIM1->CCR2  = __TIM1_CCR2;                            //
      TIM1->CCR3  = __TIM1_CCR3;                            //
      TIM1->CCR4  = __TIM1_CCR4;                            //
      TIM1->CCMR1 = __TIM1_CCMR1;                           //
      TIM1->CCMR2 = __TIM1_CCMR2;                           //
      TIM1->CCER  = __TIM1_CCER;                            // set capture/compare enable register
      TIM1->SMCR  = __TIM1_SMCR;                            // set slave mode control register

      TIM1->CR1 = __TIM1_CR1;                               // set command register 1
      TIM1->CR2 = __TIM1_CR2;                               // set command register 2
    }

    if (__TIMER_INTERRUPTS & 0x01) {                        // interrupts used
      TIM1->DIER = __TIM1_DIER;                             // enable interrupt
      NVIC->ISER[0] |= (1 << (TIM1_UP_IRQChannel & 0x1F));  // enable interrupt
    }

    TIM1->CR1 |= TIMX_CR1_CEN;                              // enable timer
  } // end TIM1 used

  if (__TIMER_USED & 0x02) {                                // TIM2 used
    RCC->APB1ENR |= RCC_APB1ENR_TIM2EN;                     // enable clock for TIM2

    TIM2->PSC = __PSC(__TIMXCLK, __TIM2_PERIOD);            // set prescaler
    TIM2->ARR = __ARR(__TIMXCLK, __TIM2_PERIOD);            // set auto-reload

    TIM2->CR1 = 0;                                          // reset command register 1
    TIM2->CR2 = 0;                                          // reset command register 2

    if (__TIMER_DETAILS & 0x02) {                           // detailed settings used
      TIM2->PSC = __TIM2_PSC;                               // set prescaler
      TIM2->ARR = __TIM2_ARR;                               // set auto-reload

      TIM2->CCR1  = __TIM2_CCR1;                            //
      TIM2->CCR2  = __TIM2_CCR2;                            //
      TIM2->CCR3  = __TIM2_CCR3;                            //
      TIM2->CCR4  = __TIM2_CCR4;                            //
      TIM2->CCMR1 = __TIM2_CCMR1;                           //
      TIM2->CCMR2 = __TIM2_CCMR2;                           //
      TIM2->CCER  = __TIM2_CCER;                            // set capture/compare enable register
      TIM2->SMCR  = __TIM2_SMCR;                            // set slave mode control register

      TIM2->CR1 = __TIM2_CR1;                               // set command register 1
      TIM2->CR2 = __TIM2_CR2;                               // set command register 2
    }

    if (__TIMER_INTERRUPTS & 0x02) {                        // interrupts used
      TIM2->DIER = __TIM2_DIER;                             // enable interrupt
      NVIC->ISER[0] |= (1 << (TIM2_IRQChannel & 0x1F));     // enable interrupt
    }

    TIM2->CR1 |= TIMX_CR1_CEN;                              // enable timer
  } // end TIM2 used

  if (__TIMER_USED & 0x04) {                                // TIM3 used
    RCC->APB1ENR |= RCC_APB1ENR_TIM3EN;                     // enable clock for TIM3

    TIM3->PSC = __PSC(__TIMXCLK, __TIM3_PERIOD);            // set prescaler
    TIM3->ARR = __ARR(__TIMXCLK, __TIM3_PERIOD);            // set auto-reload

    TIM3->CR1 = 0;                                          // reset command register 1
    TIM3->CR2 = 0;                                          // reset command register 2

    if (__TIMER_DETAILS & 0x04) {                           // detailed settings used
      TIM3->PSC = __TIM3_PSC;                               // set prescaler
      TIM3->ARR = __TIM3_ARR;                               // set auto-reload

      TIM3->CCR1  = __TIM3_CCR1;                            //
      TIM3->CCR2  = __TIM3_CCR2;                            //
      TIM3->CCR3  = __TIM3_CCR3;                            //
      TIM3->CCR4  = __TIM3_CCR4;                            //
      TIM3->CCMR1 = __TIM3_CCMR1;                           //
      TIM3->CCMR2 = __TIM3_CCMR2;                           //
      TIM3->CCER  = __TIM3_CCER;                            // set capture/compare enable register
      TIM3->SMCR  = __TIM3_SMCR;                            // set slave mode control register

      TIM3->CR1 = __TIM3_CR1;                               // set command register 1
      TIM3->CR2 = __TIM3_CR2;                               // set command register 2
    }

    if (__TIMER_INTERRUPTS & 0x04) {                        // interrupts used
      TIM3->DIER = __TIM3_DIER;                             // enable interrupt
      NVIC->ISER[0] |= (1 << (TIM3_IRQChannel & 0x1F));     // enable interrupt
    }

    TIM3->CR1 |= TIMX_CR1_CEN;                              // enable timer
  } // end TIM3 used

  if (__TIMER_USED & 0x08) {                                // TIM4 used
    RCC->APB1ENR |= RCC_APB1ENR_TIM4EN;                     // enable clock for TIM4

    TIM4->PSC = __PSC(__TIMXCLK, __TIM4_PERIOD);            // set prescaler
    TIM4->ARR = __ARR(__TIMXCLK, __TIM4_PERIOD);            // set auto-reload

    TIM4->CR1 = 0;                                          // reset command register 1
    TIM4->CR2 = 0;                                          // reset command register 2

    if (__TIMER_DETAILS & 0x08) {                           // detailed settings used
      TIM4->PSC = __TIM4_PSC;                               // set prescaler
      TIM4->ARR = __TIM4_ARR;                               // set auto-reload

      TIM4->CCR1  = __TIM4_CCR1;                            //
      TIM4->CCR2  = __TIM4_CCR2;                            //
      TIM4->CCR3  = __TIM4_CCR3;                            //
      TIM4->CCR4  = __TIM4_CCR4;                            //
      TIM4->CCMR1 = __TIM4_CCMR1;                           //
      TIM4->CCMR2 = __TIM4_CCMR2;                           //
      TIM4->CCER  = __TIM4_CCER;                            // set capture/compare enable register
      TIM4->SMCR  = __TIM4_SMCR;                            // set slave mode control register

      TIM4->CR1 = __TIM4_CR1;                               // set command register 1
      TIM4->CR2 = __TIM4_CR2;                               // set command register 2
    }

    if (__TIMER_INTERRUPTS & 0x08) {                        // interrupts used
      TIM4->DIER = __TIM4_DIER;                             // enable interrupt
      NVIC->ISER[0] |= (1 << (TIM4_IRQChannel & 0x1F));     // enable interrupt
    }

    TIM4->CR1 |= TIMX_CR1_CEN;                              // enable timer
  } // end TIM4 used

} // end of stm32_TimSetup
#endif


#if __GPIO_SETUP
/*----------------------------------------------------------------------------
 STM32 GPIO setup.
 initializes the GPIOx_CRL and GPIOxCRH register
 *----------------------------------------------------------------------------*/
__inline static void stm32_GpioSetup (void) {
  
  if (__GPIO_USED & 0x01) {                        // GPIO Port A used
    RCC->APB2ENR |= RCC_APB2ENR_IOPAEN;            // enable clock for GPIOA
    GPIOA->CRL = __GPIOA_CRL;                      // set Port configuration register low
    GPIOA->CRH = __GPIOA_CRH;                      // set Port configuration register high
  }

  if (__GPIO_USED & 0x02) {                        // GPIO Port B used
    RCC->APB2ENR |= RCC_APB2ENR_IOPBEN;            // enable clock for GPIOB
    GPIOB->CRL = __GPIOB_CRL;                      // set Port configuration register low
    GPIOB->CRH = __GPIOB_CRH;                      // set Port configuration register high
  }

  if (__GPIO_USED & 0x04) {                        // GPIO Port C used
    RCC->APB2ENR |= RCC_APB2ENR_IOPCEN;            // enable clock for GPIOC
    GPIOC->CRL = __GPIOC_CRL;                      // set Port configuration register low
    GPIOC->CRH = __GPIOC_CRH;                      // set Port configuration register high
  }

  if (__GPIO_USED & 0x08) {                        // GPIO Port D used
    RCC->APB2ENR |= RCC_APB2ENR_IOPDEN;            // enable clock for GPIOD
    GPIOD->CRL = __GPIOD_CRL;                      // set Port configuration register low
    GPIOD->CRH = __GPIOD_CRH;                      // set Port configuration register high
  }

  if (__GPIO_USED & 0x10) {                        // GPIO Port E used
    RCC->APB2ENR |= RCC_APB2ENR_IOPEEN;            // enable clock for GPIOE
    GPIOE->CRL = __GPIOE_CRL;                      // set Port configuration register low
    GPIOE->CRH = __GPIOE_CRH;                      // set Port configuration register high
  }

  if (__GPIO_USED & 0x20) {                        // GPIO Port F used
    RCC->APB2ENR |= RCC_APB2ENR_IOPFEN;            // enable clock for GPIOF
    GPIOF->CRL = __GPIOF_CRL;                      // set Port configuration register low
    GPIOF->CRH = __GPIOF_CRH;                      // set Port configuration register high
  }

  if (__GPIO_USED & 0x40) {                        // GPIO Port G used
    RCC->APB2ENR |= RCC_APB2ENR_IOPGEN;            // enable clock for GPIOG
    GPIOG->CRL = __GPIOG_CRL;                      // set Port configuration register low
    GPIOG->CRH = __GPIOG_CRH;                      // set Port configuration register high
  }

} // end of stm32_GpioSetup
#endif


#if __USART_SETUP
/*----------------------------------------------------------------------------
 STM32 USART setup.
 initializes the USARTx register
 *----------------------------------------------------------------------------*/
__inline static void stm32_UsartSetup (void) {
                                                    
  if (__USART_USED & 0x01) {                                // USART1 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR   &= ~(1 << 2);                              // clear USART1 remap
    if      ((__USART1_REMAP & 0x04) == 0x00) {             // USART1 no remap
      RCC->APB2ENR |= RCC_APB2ENR_IOPAEN;                   // enable clock for GPIOA
      GPIOA->CRH   &= ~(0xFFUL  << 4);                      // Clear PA9, PA10
      GPIOA->CRH   |=  (0x0BUL  << 4);                      // USART1 Tx (PA9)  alternate output push-pull
      GPIOA->CRH   |=  (0x04UL  << 8);                      // USART1 Rx (PA10) input floating
    }
    else {                                                  // USART1    remap
      RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                   // enable clock for Alternate Function
      AFIO->MAPR   |= __USART1_REMAP;                       // set   USART1 remap
      RCC->APB2ENR |= RCC_APB2ENR_IOPBEN;                   // enable clock for GPIOB
      GPIOB->CRL   &= ~(0xFFUL  << 24);                     // Clear PB6, PB7
      GPIOB->CRL   |=  (0x0BUL  << 24);                     // USART1 Tx (PB6)  alternate output push-pull
      GPIOB->CRL   |=  (0x04UL  << 28);                     // USART1 Rx (PB7) input floating
    }

    RCC->APB2ENR |= RCC_APB2ENR_USART1EN;                   // enable clock for USART1
        
    USART1->BRR  = __USART_BRR(__PCLK2, __USART1_BAUDRATE); // set baudrate
    USART1->CR1  = __USART1_DATABITS;                       // set Data bits
    USART1->CR2  = __USART1_STOPBITS;                       // set Stop bits
    USART1->CR1 |= __USART1_PARITY;                         // set Parity
    USART1->CR3  = __USART1_FLOWCTRL;                       // Set Flow Control

    USART1->CR1 |= (USART_CR1_RE | USART_CR1_TE);           // RX, TX enable

    if (__USART_INTERRUPTS & 0x01) {                        // interrupts used
      USART1->CR1 |= __USART1_CR1;
      USART1->CR2 |= __USART1_CR2;
      USART1->CR3 |= __USART1_CR3;
      NVIC->ISER[1] |= (1 << (USART1_IRQChannel & 0x1F));   // enable interrupt
    }

    USART1->CR1 |= USART_CR1_UE;                            // USART enable
  } // end USART1 used

  if (__USART_USED & 0x02) {                                // USART2 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR   &= ~(1 << 3);                              // clear USART2 remap
    if      ((__USART2_REMAP & 0x08) == 0x00) {             // USART2 no remap
      RCC->APB2ENR |=  RCC_APB2ENR_IOPAEN;                  // enable clock for GPIOA
      GPIOA->CRL   &= ~(0xFFUL  << 8);                      // Clear PA2, PA3
      GPIOA->CRL   |=  (0x0BUL  << 8);                      // USART2 Tx (PA2)  alternate output push-pull
      GPIOA->CRL   |=  (0x04UL  << 12);                     // USART2 Rx (PA3)  input floating
      if (__USART2_FLOWCTRL & 0x0300) {                     // HW flow control enabled
        GPIOA->CRL   &= ~(0xFFUL  << 0);                    // Clear PA0, PA1
        GPIOA->CRL   |=  (0x04UL  << 0);                    // USART2 CTS (PA0) input floating
        GPIOA->CRL   |=  (0x0BUL  << 4);                    // USART2 RTS (PA1) alternate output push-pull
      }
    }                                                
    else {                                                  // USART2    remap
      RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                   // enable clock for Alternate Function
      AFIO->MAPR   |= __USART2_REMAP;                       // set   USART2 remap
      RCC->APB2ENR |=  RCC_APB2ENR_IOPDEN;                  // enable clock for GPIOD
      GPIOD->CRL   &= ~(0xFFUL  << 20);                     // Clear PD5, PD6
      GPIOD->CRL   |=  (0x0BUL  << 20);                     // USART2 Tx (PD5)  alternate output push-pull
      GPIOD->CRL   |=  (0x04UL  << 24);                     // USART2 Rx (PD6)  input floating
      if (__USART2_FLOWCTRL & 0x0300) {                     // HW flow control enabled
        GPIOD->CRL   &= ~(0xFFUL  << 12);                   // Clear PD3, PD4
        GPIOD->CRL   |=  (0x04UL  << 12);                   // USART2 CTS (PD3) input floating
        GPIOD->CRL   |=  (0x0BUL  << 16);                   // USART2 RTS (PD4) alternate output push-pull
      }
    }

    RCC->APB1ENR |= RCC_APB1ENR_USART2EN;                   // enable clock for USART2

    USART2->BRR  = __USART_BRR(__PCLK1, __USART2_BAUDRATE); // set baudrate
    USART2->CR1  = __USART2_DATABITS;                       // set Data bits
    USART2->CR2  = __USART2_STOPBITS;                       // set Stop bits
    USART2->CR1 |= __USART2_PARITY;                         // set Parity
    USART2->CR3  = __USART2_FLOWCTRL;                       // Set Flow Control

    USART2->CR1 |= (USART_CR1_RE | USART_CR1_TE);           // RX, TX enable

    if (__USART_INTERRUPTS & 0x02) {                        // interrupts used
      USART2->CR1 |= __USART2_CR1;
      USART2->CR2 |= __USART2_CR2;
      USART2->CR3 |= __USART2_CR3;
      NVIC->ISER[1] |= (1 << (USART2_IRQChannel & 0x1F));   // enable interrupt
    }

    USART2->CR1 |= USART_CR1_UE;                            // USART enable
  } // end USART2 used

  if (__USART_USED & 0x04) {                                // USART3 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR   &= ~(3 << 4);                              // clear USART3 remap
    if      ((__USART3_REMAP & 0x30) == 0x00) {             // USART3 no remap
      RCC->APB2ENR |=  RCC_APB2ENR_IOPBEN;                  // enable clock for GPIOB
      GPIOB->CRH   &= ~(0xFFUL  <<  8);                     // Clear PB10, PB11
      GPIOB->CRH   |=  (0x0BUL  <<  8);                     // USART3 Tx (PB10) alternate output push-pull
      GPIOB->CRH   |=  (0x04UL  << 12);                     // USART3 Rx (PB11) input floating
      if (__USART3_FLOWCTRL & 0x0300) {                     // HW flow control enabled
        GPIOB->CRH   &= ~(0xFFUL  << 20);                   // Clear PB13, PB14
        GPIOB->CRH   |=  (0x04UL  << 20);                   // USART3 CTS (PB13) input floating
        GPIOB->CRH   |=  (0x0BUL  << 24);                   // USART3 RTS (PB14) alternate output push-pull
      }
    }
    else if ((__USART3_REMAP & 0x30) == 0x10) {             // USART3 partial remap
      RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                   // enable clock for Alternate Function
      AFIO->MAPR   |= __USART3_REMAP;                       // set   USART3 remap
      RCC->APB2ENR |=  RCC_APB2ENR_IOPCEN;                  // enable clock for GPIOC
      GPIOC->CRH   &= ~(0xFFUL  <<  8);                     // Clear PC10, PC11
      GPIOC->CRH   |=  (0x0BUL  <<  8);                     // USART3 Tx (PC10) alternate output push-pull
      GPIOC->CRH   |=  (0x04UL  << 12);                     // USART3 Rx (PC11) input floating
      if (__USART3_FLOWCTRL & 0x0300) {                     // HW flow control enabled
        RCC->APB2ENR |=  RCC_APB2ENR_IOPBEN;                // enable clock for GPIOB
        GPIOB->CRH   &= ~(0xFFUL  << 20);                   // Clear PB13, PB14
        GPIOB->CRH   |=  (0x04UL  << 20);                   // USART3 CTS (PB13) input floating
        GPIOB->CRH   |=  (0x0BUL  << 24);                   // USART3 RTS (PB14) alternate output push-pull
      }
    }
    else {                                                  // USART3 full remap
      RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                   // enable clock for Alternate Function
      AFIO->MAPR   |= __USART3_REMAP;                       // set   USART3 remap
      RCC->APB2ENR |=  RCC_APB2ENR_IOPDEN;                  // enable clock for GPIOD
      GPIOD->CRH   &= ~(0xFFUL  <<  0);                     // Clear PD8, PD9
      GPIOD->CRH   |=  (0x0BUL  <<  0);                     // USART3 Tx (PD8) alternate output push-pull
      GPIOD->CRH   |=  (0x04UL  <<  4);                     // USART3 Rx (PD9) input floating
      if (__USART3_FLOWCTRL & 0x0300) {                     // HW flow control enabled
        GPIOD->CRH   &= ~(0xFFUL  << 12);                   // Clear PD11, PD12
        GPIOD->CRH   |=  (0x04UL  << 12);                   // USART3 CTS (PD11) input floating
        GPIOD->CRH   |=  (0x0BUL  << 16);                   // USART3 RTS (PD12) alternate output push-pull
      }
    } 

    RCC->APB1ENR |= RCC_APB1ENR_USART3EN;                   // enable clock for USART3

    USART3->BRR  = __USART_BRR(__PCLK1, __USART3_BAUDRATE); // set baudrate
    USART3->CR1  = __USART3_DATABITS;                       // set Data bits
    USART3->CR2  = __USART3_STOPBITS;                       // set Stop bits
    USART3->CR1 |= __USART3_PARITY;                         // set Parity
    USART3->CR3  = __USART3_FLOWCTRL;                       // Set Flow Control

    USART3->CR1 |= (USART_CR1_RE | USART_CR1_TE);           // RX, TX enable

    if (__USART_INTERRUPTS & 0x04) {                        // interrupts used
      USART3->CR1 |= __USART3_CR1;
      USART3->CR2 |= __USART3_CR2;
      USART3->CR3 |= __USART3_CR3;
      NVIC->ISER[1] |= (1 << (USART3_IRQChannel & 0x1F));   // enable interrupt
    }

    USART3->CR1 |= USART_CR1_UE;                            // USART enable
  } // end USART3 used


} // end of stm32_UsartSetup
#endif


#if __EXTI_SETUP
/*----------------------------------------------------------------------------
 STM32 EXTI setup.
 initializes the EXTI register
 *----------------------------------------------------------------------------*/
__inline static void stm32_ExtiSetup (void) {
                                                    
  if (__EXTI_USED & (1 << 0)) {                             // EXTI0 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[0] &= 0xFFF0;                              // clear used pin
    AFIO->EXTICR[0] |= (0x000F & __AFIO_EXTICR1);           // set pin to use

    EXTI->IMR       |= ((1 << 0) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 0) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 0) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 0) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 0)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI0_IRQChannel & 0x1F));    // enable interrupt EXTI 0
    }
  } // end EXTI0 used

  if (__EXTI_USED & (1 << 1)) {                             // EXTI1 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[0] &= 0xFF0F;                              // clear used pin
    AFIO->EXTICR[0] |= (0x00F0 & __AFIO_EXTICR1);           // set pin to use

    EXTI->IMR       |= ((1 << 1) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 1) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 1) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 1) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 1)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI1_IRQChannel & 0x1F));    // enable interrupt EXTI 1
    }
  } // end EXTI1 used

  if (__EXTI_USED & (1 << 2)) {                             // EXTI2 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[0] &= 0xF0FF;                              // clear used pin
    AFIO->EXTICR[0] |= (0x0F00 & __AFIO_EXTICR1);           // set pin to use

    EXTI->IMR       |= ((1 << 2) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 2) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 2) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 2) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 2)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI2_IRQChannel & 0x1F));    // enable interrupt EXTI 2
    }
  } // end EXTI2 used

  if (__EXTI_USED & (1 << 3)) {                             // EXTI3 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[0] &= 0x0FFF;                              // clear used pin
    AFIO->EXTICR[0] |= (0xFF00 & __AFIO_EXTICR1);           // set pin to use

    EXTI->IMR       |= ((1 << 3) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 3) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 3) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 3) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 3)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI3_IRQChannel & 0x1F));    // enable interrupt EXTI 3
    }
  } // end EXTI3 used

  if (__EXTI_USED & (1 << 4)) {                             // EXTI4 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[1] &= 0xFFF0;                              // clear used pin
    AFIO->EXTICR[1] |= (0x000F & __AFIO_EXTICR2);           // set pin to use

    EXTI->IMR       |= ((1 << 4) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 4) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 4) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 4) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 4)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI4_IRQChannel & 0x1F));    // enable interrupt EXTI 4
    }
  } // end EXTI4 used

  if (__EXTI_USED & (1 << 5)) {                             // EXTI5 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[1] &= 0xFF0F;                              // clear used pin
    AFIO->EXTICR[1] |= (0x00F0 & __AFIO_EXTICR2);           // set pin to use

    EXTI->IMR       |= ((1 << 5) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 5) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 5) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 5) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 5)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI9_5_IRQChannel & 0x1F));  // enable interrupt EXTI 9..5
    }
  } // end EXTI5 used

  if (__EXTI_USED & (1 << 6)) {                             // EXTI6 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[1] &= 0xF0FF;                              // clear used pin
    AFIO->EXTICR[1] |= (0x0F00 & __AFIO_EXTICR2);           // set pin to use

    EXTI->IMR       |= ((1 << 6) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 6) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 6) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 6) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 6)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI9_5_IRQChannel & 0x1F));  // enable interrupt EXTI 9..5
    }
  } // end EXTI6 used

  if (__EXTI_USED & (1 << 7)) {                             // EXTI7 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[1] &= 0x0FFF;                              // clear used pin
    AFIO->EXTICR[1] |= (0xF000 & __AFIO_EXTICR2);           // set pin to use

    EXTI->IMR       |= ((1 << 7) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 7) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 7) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 7) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 7)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI9_5_IRQChannel & 0x1F));  // enable interrupt EXTI 9..5
    }
  } // end EXTI7 used

  if (__EXTI_USED & (1 << 8)) {                             // EXTI8 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[2] &= 0xFFF0;                              // clear used pin
    AFIO->EXTICR[2] |= (0x000F & __AFIO_EXTICR3);           // set pin to use

    EXTI->IMR       |= ((1 << 8) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 8) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 8) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 8) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 8)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI9_5_IRQChannel & 0x1F));  // enable interrupt EXTI 9..5
    }
  } // end EXTI8 used

  if (__EXTI_USED & (1 << 9)) {                             // EXTI9 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[2] &= 0xFF0F;                              // clear used pin
    AFIO->EXTICR[2] |= (0x00F0 & __AFIO_EXTICR3);           // set pin to use

    EXTI->IMR       |= ((1 << 9) & __EXTI_IMR);             // unmask interrupt
    EXTI->EMR       |= ((1 << 9) & __EXTI_EMR);             // unmask event
    EXTI->RTSR      |= ((1 << 9) & __EXTI_RTSR);            // set rising edge
    EXTI->FTSR      |= ((1 << 9) & __EXTI_FTSR);            // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 9)) {                     // interrupt used
      NVIC->ISER[0] |= (1 << (EXTI9_5_IRQChannel & 0x1F));  // enable interrupt EXTI 9..5
    }
  } // end EXTI9 used

  if (__EXTI_USED & (1 << 10)) {                            // EXTI10 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[2] &= 0xF0FF;                              // clear used pin
    AFIO->EXTICR[2] |= (0x0F00 & __AFIO_EXTICR3);           // set pin to use

    EXTI->IMR       |= ((1 << 10) & __EXTI_IMR);            // unmask interrupt
    EXTI->EMR       |= ((1 << 10) & __EXTI_EMR);            // unmask event
    EXTI->RTSR      |= ((1 << 10) & __EXTI_RTSR);           // set rising edge
    EXTI->FTSR      |= ((1 << 10) & __EXTI_FTSR);           // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 10)) {                    // interrupt used
      NVIC->ISER[1] |= (1 << (EXTI15_10_IRQChannel & 0x1F));// enable interrupt EXTI 10..15
    }
  } // end EXTI10 used

  if (__EXTI_USED & (1 << 11)) {                            // EXTI11 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[2] &= 0x0FFF;                              // clear used pin
    AFIO->EXTICR[2] |= (0xF000 & __AFIO_EXTICR3);           // set pin to use

    EXTI->IMR       |= ((1 << 11) & __EXTI_IMR);            // unmask interrupt
    EXTI->EMR       |= ((1 << 11) & __EXTI_EMR);            // unmask event
    EXTI->RTSR      |= ((1 << 11) & __EXTI_RTSR);           // set rising edge
    EXTI->FTSR      |= ((1 << 11) & __EXTI_FTSR);           // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 11)) {                    // interrupt used
      NVIC->ISER[1] |= (1 << (EXTI15_10_IRQChannel & 0x1F));// enable interrupt EXTI 10..15
    }
  } // end EXTI11 used

  if (__EXTI_USED & (1 << 12)) {                            // EXTI12 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[3] &= 0xFFF0;                              // clear used pin
    AFIO->EXTICR[3] |= (0x000F & __AFIO_EXTICR4);           // set pin to use

    EXTI->IMR       |= ((1 << 12) & __EXTI_IMR);            // unmask interrupt
    EXTI->EMR       |= ((1 << 12) & __EXTI_EMR);            // unmask event
    EXTI->RTSR      |= ((1 << 12) & __EXTI_RTSR);           // set rising edge
    EXTI->FTSR      |= ((1 << 12) & __EXTI_FTSR);           // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 12)) {                    // interrupt used
      NVIC->ISER[1] |= (1 << (EXTI15_10_IRQChannel & 0x1F));// enable interrupt EXTI 10..15
    }
  } // end EXTI12 used

  if (__EXTI_USED & (1 << 13)) {                            // EXTI13 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[3] &= 0xFF0F;                              // clear used pin
    AFIO->EXTICR[3] |= (0x00F0 & __AFIO_EXTICR4);           // set pin to use

    EXTI->IMR       |= ((1 << 13) & __EXTI_IMR);            // unmask interrupt
    EXTI->EMR       |= ((1 << 13) & __EXTI_EMR);            // unmask event
    EXTI->RTSR      |= ((1 << 13) & __EXTI_RTSR);           // set rising edge
    EXTI->FTSR      |= ((1 << 13) & __EXTI_FTSR);           // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 13)) {                    // interrupt used
      NVIC->ISER[1] |= (1 << (EXTI15_10_IRQChannel & 0x1F));// enable interrupt EXTI 10..15
    }
  } // end EXTI13 used

  if (__EXTI_USED & (1 << 14)) {                            // EXTI14 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[3] &= 0xF0FF;                              // clear used pin
    AFIO->EXTICR[3] |= (0x0F00 & __AFIO_EXTICR4);           // set pin to use

    EXTI->IMR       |= ((1 << 14) & __EXTI_IMR);            // unmask interrupt
    EXTI->EMR       |= ((1 << 14) & __EXTI_EMR);            // unmask event
    EXTI->RTSR      |= ((1 << 14) & __EXTI_RTSR);           // set rising edge
    EXTI->FTSR      |= ((1 << 14) & __EXTI_FTSR);           // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 14)) {                    // interrupt used
      NVIC->ISER[1] |= (1 << (EXTI15_10_IRQChannel & 0x1F));// enable interrupt EXTI 10..15
    }
  } // end EXTI14 used

  if (__EXTI_USED & (1 << 15)) {                            // EXTI15 used

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->EXTICR[3] &= 0x0FFF;                              // clear used pin
    AFIO->EXTICR[3] |= (0xF000 & __AFIO_EXTICR4);           // set pin to use

    EXTI->IMR       |= ((1 << 15) & __EXTI_IMR);            // unmask interrupt
    EXTI->EMR       |= ((1 << 15) & __EXTI_EMR);            // unmask event
    EXTI->RTSR      |= ((1 << 15) & __EXTI_RTSR);           // set rising edge
    EXTI->FTSR      |= ((1 << 15) & __EXTI_FTSR);           // set falling edge

    if (__EXTI_INTERRUPTS & (1 << 15)) {                    // interrupt used
      NVIC->ISER[1] |= (1 << (EXTI15_10_IRQChannel & 0x1F));// enable interrupt EXTI 10..15
    }
  } // end EXTI15 used

} // end of stm32_ExtiSetup
#endif


#if __AFREMAP_SETUP
/*----------------------------------------------------------------------------
 STM32 AF remap setup.
 initializes the AFIO_MAPR register
 *----------------------------------------------------------------------------*/
__inline static void stm32_AfRemapSetup (void) {
                                                    
  if (__AFIO_MAPR & (1 << 0)) {                             // SPI1 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(1 << 0);                                // clear used bit
    AFIO->MAPR |= ((1 << 0) & __AFIO_MAPR);                 // set used bits
  } // end SPI1 remap used

  if (__AFIO_MAPR & (1 << 1)) {                             // I2C1 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(1 << 1);                                // clear used bit
    AFIO->MAPR |= ((1 << 1) & __AFIO_MAPR);                 // set used bits
  } // end I2C1 remap used

  if (__AFIO_MAPR & (1 << 2)) {                             // USART1 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(1 << 2);                                // clear used bit
    AFIO->MAPR |= ((1 << 2) & __AFIO_MAPR);                 // set used bits
  } // end USART1 remap used

  if (__AFIO_MAPR & (1 << 3)) {                             // USART2 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(1 << 3);                                // clear used bit
    AFIO->MAPR |= ((1 << 3) & __AFIO_MAPR);                 // set used bits
  } // end USART2 remap used

  if (__AFIO_MAPR & (3 << 4)) {                             // USART3 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(3 << 4);                                // clear used bit
    AFIO->MAPR |= ((3 << 4) & __AFIO_MAPR);                 // set used bits
  } // end USART3 remap used

  if (__AFIO_MAPR & (3 << 6)) {                             // TIM1 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(3 << 6);                                // clear used bit
    AFIO->MAPR |= ((3 << 6) & __AFIO_MAPR);                 // set used bits
  } // end TIM1 remap used

  if (__AFIO_MAPR & (3 << 8)) {                             // TIM2 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(3 << 8);                                // clear used bit
    AFIO->MAPR |= ((3 << 8) & __AFIO_MAPR);                 // set used bits
  } // end TIM2 remap used

  if (__AFIO_MAPR & (3 << 10)) {                            // TIM3 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(3 << 10);                               // clear used bit
    AFIO->MAPR |= ((3 << 10) & __AFIO_MAPR);                // set used bits
  } // end TIM3 remap used

  if (__AFIO_MAPR & (1 << 12)) {                            // TIM4 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(1 << 12);                               // clear used bit
    AFIO->MAPR |= ((1 << 12) & __AFIO_MAPR);                // set used bits
  } // end TIM2 remap used

  if (__AFIO_MAPR & (3 << 13)) {                            // CAN remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(3 << 13);                               // clear used bit
    AFIO->MAPR |= ((3 << 13) & __AFIO_MAPR);                // set used bits
  } // end TIM2 remap used

  if (__AFIO_MAPR & (1 << 15)) {                            // PD01 remap used 

    RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;                     // enable clock for Alternate Function
    AFIO->MAPR &= ~(1 << 15);                               // clear used bit
    AFIO->MAPR |= ((1 << 15) & __AFIO_MAPR);                // set used bits
  } // end TIM2 remap used

} // end of stm32_AfRemapSetup
#endif



#if __TAMPER_SETUP
/*----------------------------------------------------------------------------
 STM32 Tamper setup.
 initializes the Tamper register
 *----------------------------------------------------------------------------*/
__inline static void stm32_TamperSetup (void) {

  RCC->APB1ENR |= RCC_APB1ENR_BKPEN;                        // enable clock for Backup interface
  RCC->APB1ENR |= RCC_APB1ENR_PWREN;                        // enable clock for Power interface

  PWR->CR  |= PWR_CR_DBP;                                   // enable access to RTC, BDC registers
  BKP->CR   = __BKP_CR;                                     // set BKP_CR register
  BKP->CSR  = __BKP_CSR;                                    // set BKP_CSR register
  BKP->CSR |= 0x0003;                                       // clear CTI, CTE
  PWR->CR  &= ~PWR_CR_DBP;                                  // disable access to RTC, BDC registers

  if (BKP->CSR & (1<<2)) {                                  // Tamper interrupt enable ?
    NVIC->ISER[0] |= (1 << (TAMPER_IRQChannel & 0x1F));     // enable interrupt
  }
                                                      
} // end of stm32_TamperSetup
#endif


/*----------------------------------------------------------------------------
 STM32 initialization
 Call this function as first in main ()
 *----------------------------------------------------------------------------*/
void stm32_Init () {

#if __EFI_SETUP
  stm32_EfiSetup ();
#endif

#if __CLOCK_SETUP
  stm32_ClockSetup ();
#endif

#if __NVIC_SETUP
  stm32_NvicSetup ();
#endif

#if __SYSTICK_SETUP
  stm32_SysTickSetup ();
#endif

#if __RTC_SETUP
  stm32_RtcSetup ();
#endif

#if __TIMER_SETUP
  stm32_TimerSetup ();
#endif

#if __AFREMAP_SETUP
  stm32_AfRemapSetup ();
#endif

#if __GPIO_SETUP
  stm32_GpioSetup ();
#endif

#if __USART_SETUP
  stm32_UsartSetup();
#endif

#if __EXTI_SETUP
  stm32_ExtiSetup();
#endif

#if __TAMPER_SETUP
  stm32_TamperSetup();
#endif

#if __IWDG_SETUP
  stm32_IwdgSetup();   // this should be the last function. watchdog is running afterwards
#endif

} // end of stm32_Init


/*----------------------------------------------------------------------------
 STM32 get PCLK1
 deliver the PCLK1
 *----------------------------------------------------------------------------*/
unsigned int stm32_GetPCLK1 (void) {
  return ((unsigned int)__PCLK1);
}


/*----------------------------------------------------------------------------
 STM32 get PCLK2
 deliver the PCLK2
 *----------------------------------------------------------------------------*/
unsigned int stm32_GetPCLK2 (void) {
  return ((unsigned int)__PCLK2);
}
