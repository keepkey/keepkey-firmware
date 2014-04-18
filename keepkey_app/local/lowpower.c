/**
  ******************************************************************************
  * @file    lowpower.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   This file includes the low power driver for the STM3210E-EVAL
  *          demonstration.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2013 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Liberty SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        http://www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software 
  * distributed under the License is distributed on an "AS IS" BASIS, 
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
static __IO uint32_t STOPModeStatus = 0;
static uint32_t GPIOA_CRL = 0, GPIOA_CRH = 0, GPIOB_CRL = 0, GPIOB_CRH = 0,
           GPIOC_CRL = 0, GPIOC_CRH = 0, GPIOD_CRL = 0, GPIOD_CRH = 0,
           GPIOE_CRL = 0, GPIOE_CRH = 0, GPIOF_CRL = 0, GPIOF_CRH = 0,
           GPIOG_CRL = 0, GPIOG_CRH = 0;
/* Private function prototypes -----------------------------------------------*/
static void GPIO_SaveConfig(void);
static void GPIO_RestoreConfig(void);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Initializes Low Power application.
  * @param  None
  * @retval  None
  */
void LowPower_Init(void)
{
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_PWR, ENABLE);

  /* Enable WakeUp pin */
  PWR_WakeUpPinCmd(ENABLE);

  /* Enable Clock Security System(CSS) */
  RCC_ClockSecuritySystemCmd(ENABLE);
}

/**
  * @brief  Configures system clock after wake-up from STOP: enable HSE, PLL 
  *         and select PLL as system clock source.
  * @param  None
  * @retval  None
  */
void SYSCLKConfig_STOP(void)
{
  ErrorStatus HSEStartUpStatus;

  /* Enable HSE */
  RCC_HSEConfig(RCC_HSE_ON);

  /* Wait till HSE is ready */
  HSEStartUpStatus = RCC_WaitForHSEStartUp();

  if(HSEStartUpStatus == SUCCESS)
  {
    /* Enable PLL */ 
    RCC_PLLCmd(ENABLE);

    /* Wait till PLL is ready */
    while(RCC_GetFlagStatus(RCC_FLAG_PLLRDY) == RESET)
    {
    }

    /* Select PLL as system clock source */
    RCC_SYSCLKConfig(RCC_SYSCLKSource_PLLCLK);

    /* Wait till PLL is used as system clock source */
    while(RCC_GetSYSCLKSource() != 0x08)
    {
    }
  }
}

/**
  * @brief  Enters MCU in STOP mode. The wake-up from STOP mode is performed by 
  *         an external interrupt.
  * @param  None
  * @retval  None
  */
void EnterSTOPMode_EXTI(void)
{
  NVIC_InitTypeDef NVIC_InitStructure;
  EXTI_InitTypeDef EXTI_InitStructure;

  STOPModeStatus = 0;

  /* Clear the LCD */
  LCD_Clear(White);

  /* Set the LCD Back Color */
  LCD_SetBackColor(Blue);

  /* Set the LCD Text Color */
  LCD_SetTextColor(White);

  /* Disable the JoyStick interrupts */
  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }

  /* Configure the EXTI Line 8 */
  EXTI_InitStructure.EXTI_Mode = EXTI_Mode_Interrupt;
  EXTI_InitStructure.EXTI_Line = EXTI_Line8;
  EXTI_InitStructure.EXTI_Trigger = EXTI_Trigger_Falling;
  EXTI_InitStructure.EXTI_LineCmd = ENABLE;
  EXTI_Init(&EXTI_InitStructure);

  /* Enable the EXTI0 Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = EXTI9_5_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

  LCD_DisplayStringLine(Line4, "Typical current     "); 
  LCD_DisplayStringLine(Line5, "consumption in STOP ");
  LCD_DisplayStringLine(Line6, "mode with low power ");
  LCD_DisplayStringLine(Line7, "regulator is: 25 uA ");
  LCD_DisplayStringLine(Line8, "Pess SEL to continue");

  while(ReadKey() != SEL)
  {
  } 

  while(ReadKey() != NOKEY)
  {
  }
  LCD_ClearLine(Line7);
  LCD_ClearLine(Line8);
  LCD_ClearLine(Line9);
  LCD_DisplayStringLine(Line4, "  MCU in STOP Mode  "); 
  LCD_DisplayStringLine(Line5, "To exit press Key   ");
  LCD_DisplayStringLine(Line6, "push button         ");

  /* Clear the RTC Alarm flag */
  RTC_ClearFlag(RTC_FLAG_ALR);

  /* Save the GPIO pins current configuration then put all GPIO pins in Analog
     Input mode ...*/
  GPIO_SaveConfig();

  /* ... and keep PG.08 configuration which will be used as EXTI Line8 source */
  GPIOG->CRH = 0x4;

  /* Request to enter STOP mode with regulator in low power */
  PWR_EnterSTOPMode(PWR_Regulator_LowPower, PWR_STOPEntry_WFI);

  /* Restore the GPIO Configurations*/
  GPIO_RestoreConfig();

/* At this stage the system has resumed from STOP mode ************************/
  EXTI_InitStructure.EXTI_Mode = EXTI_Mode_Interrupt;
  EXTI_InitStructure.EXTI_Line = EXTI_Line8;
  EXTI_InitStructure.EXTI_Trigger = EXTI_Trigger_Falling;
  EXTI_InitStructure.EXTI_LineCmd = DISABLE;
  EXTI_Init(&EXTI_InitStructure);

  /* Enable the EXTI9_5 Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = EXTI9_5_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 2;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

  /* Configures system clock after wake-up from STOP: enable HSE, PLL and select PLL
     as system clock source (HSE and PLL are disabled in STOP mode) */
  SYSCLKConfig_STOP();

  while(ReadKey() != NOKEY)
  {
  }

  if(STOPModeStatus != RESET)
  {
    LCD_DisplayStringLine(Line4, "      STOP Mode     ");
    LCD_DisplayStringLine(Line5, "Wake-Up by RTC Alarm");
    LCD_DisplayStringLine(Line6, "Press JoyStick to   ");
    LCD_DisplayStringLine(Line7, "continue...         ");
  }
  else
  {
    LCD_DisplayStringLine(Line4, "      STOP Mode     ");
    LCD_DisplayStringLine(Line5, "WakeUp by Key Button");
    LCD_DisplayStringLine(Line6, "Press JoyStick to   ");
    LCD_DisplayStringLine(Line7, "continue...         ");
  }

  while(ReadKey() == NOKEY)
  {
  }

  /* Clear the LCD */
  LCD_Clear(White);
  /* Display the previous menu */
  DisplayMenu();
  /* Enable the JoyStick interrupts */
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Enters MCU in STOP mode. The wake-up from STOP mode is performed by 
  *         an RTC Alarm.
  * @param  None
  * @retval  None
  */
void EnterSTOPMode_RTCAlarm(void)
{
  uint32_t tmp = 0;

  /* Clear the LCD */
  LCD_Clear(White);
  /* Set the LCD Back Color */
  LCD_SetBackColor(Blue);

  /* Set the LCD Text Color */
  LCD_SetTextColor(White);

  /* Disable the JoyStick interrupts */
  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }

  if(BKP_ReadBackupRegister(BKP_DR1) != 0xA5A5)
  {
    LCD_DisplayStringLine(Line1, "Time and Date are   ");
    LCD_DisplayStringLine(Line2, "not configured,     ");
    LCD_DisplayStringLine(Line3, "please go to the    ");
    LCD_DisplayStringLine(Line4, "calendar menu and   ");
    LCD_DisplayStringLine(Line5, "set the time and    ");
    LCD_DisplayStringLine(Line6, "date parameters.    ");
    LCD_DisplayStringLine(Line7, "Press JoyStick to   ");
    LCD_DisplayStringLine(Line8, "continue...         ");
    while(ReadKey() == NOKEY)
    {
    }
    /* Clear the LCD */
    LCD_Clear(White);
    /* Display the previous menu */
    DisplayMenu();
    /* Enable the JoyStick interrupts */
    IntExtOnOffConfig(ENABLE);
    return;
  }

  LCD_DisplayStringLine(Line4, "Typical current     "); 
  LCD_DisplayStringLine(Line5, "consumption in STOP ");
  LCD_DisplayStringLine(Line6, "mode with low power ");
  LCD_DisplayStringLine(Line7, "regulator is: 25 uA ");
  LCD_DisplayStringLine(Line8, "Pess SEL to continue");

  while(ReadKey() != SEL)
  {
  }
  while(ReadKey() != NOKEY)
  {
  }

  LCD_Clear(White);
    
  tmp = RTC_GetCounter();

  /* Save the Alarm value in the Backup register */
  BKP_WriteBackupRegister(BKP_DR6, (tmp & 0x0000FFFF));
  BKP_WriteBackupRegister(BKP_DR7, (tmp >> 16));
  
  Alarm_PreAdjust();
  LCD_ClearLine(Line8);
   
  LCD_DisplayStringLine(Line6, "  MCU in STOP Mode  "); 
  LCD_DisplayStringLine(Line7, " Wait For RTC Alarm ");
  
  /* Save the GPIO pins current configuration then put all GPIO pins in Analog Input mode */
  GPIO_SaveConfig();
  
  /* Request to enter STOP mode with regulator in low power */
  PWR_EnterSTOPMode(PWR_Regulator_LowPower, PWR_STOPEntry_WFI);

  /* Restore the GPIO Configurations*/
  GPIO_RestoreConfig();

  /* Configures system clock after wake-up from STOP: enable HSE, PLL and select PLL
     as system clock source (HSE and PLL are disabled in STOP mode) */
  SYSCLKConfig_STOP();

  LCD_DisplayStringLine(Line4, "      STOP Mode     ");
  LCD_DisplayStringLine(Line5, "Wake-Up by RTC Alarm");
  LCD_DisplayStringLine(Line6, "Press JoyStick to   ");
  LCD_DisplayStringLine(Line7, "continue...         ");

  while(ReadKey() == NOKEY)
  {
  }

  /* Clear the LCD */
  LCD_Clear(White);
  /* Display the previous menu */
  DisplayMenu();
  /* Enable the JoyStick interrupts */
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Enters MCU in STANDBY mode. The wake-up from STANDBY mode is performed
  *         when a rising edge is detected on WKP_STDBY pin.
  * @param  None
  * @retval  None
  */
void EnterSTANDBYMode_WAKEUP(void)
{
  /* Clear the LCD */
  LCD_Clear(White);

  /* Set the LCD Back Color */
  LCD_SetBackColor(Blue);

  /* Set the LCD Text Color */
  LCD_SetTextColor(White);

  /* Disable the JoyStick interrupts */
  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }
 
  LCD_DisplayStringLine(Line4, "Typical current     "); 
  LCD_DisplayStringLine(Line5, "consumption in      ");
  LCD_DisplayStringLine(Line6, "STANDBY mode with   ");
  LCD_DisplayStringLine(Line7, "RTC ON is: 3.6 uA   ");
  LCD_DisplayStringLine(Line8, "PressSEL to continue");
   
  while(ReadKey() != SEL)
  {
  } 
  
  while(ReadKey() != NOKEY)
  {
  }
  LCD_ClearLine(Line4);
  LCD_ClearLine(Line5);
  LCD_ClearLine(Line6);
  LCD_ClearLine(Line9);
  
  LCD_DisplayStringLine(Line7, " MCU in STANDBY Mode"); 
  LCD_DisplayStringLine(Line8, "To exit press Wakeup");

  /* Request to enter STANDBY mode (Wake Up flag is cleared in PWR_EnterSTANDBYMode function) */
  PWR_EnterSTANDBYMode();
}

/**
  * @brief  Enters MCU in STANDBY mode. The wake-up from STANDBY mode is performed
  *         by an RTC Alarm event.
  * @param  None
  * @retval  None
  */
void EnterSTANDBYMode_RTCAlarm(void)
{
  uint32_t tmp = 0;

  LCD_Clear(White);
  /* Set the LCD Back Color */
  LCD_SetBackColor(Blue);

  /* Set the LCD Text Color */
  LCD_SetTextColor(White);

  /* Disable the JoyStick interrupts */
  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }

  if(BKP_ReadBackupRegister(BKP_DR1) != 0xA5A5)
  {
    LCD_DisplayStringLine(Line1, "Time and Date are   ");
    LCD_DisplayStringLine(Line2, "not configured,     ");
    LCD_DisplayStringLine(Line3, "please go to the    ");
    LCD_DisplayStringLine(Line4, "calendar menu and   ");
    LCD_DisplayStringLine(Line5, "set the time and    ");
    LCD_DisplayStringLine(Line6, "date parameters.    ");
    LCD_DisplayStringLine(Line7, "Press JoyStick to   ");
    LCD_DisplayStringLine(Line8, "continue...         ");
    while(ReadKey() == NOKEY)
    {
    }
    /* Clear the LCD */
    LCD_Clear(White);
    /* Display the previous menu */
    DisplayMenu();
    /* Enable the JoyStick interrupts */
    IntExtOnOffConfig(ENABLE);
    return;
  }

  LCD_DisplayStringLine(Line4, "Typical current     "); 
  LCD_DisplayStringLine(Line5, "consumption in      ");
  LCD_DisplayStringLine(Line6, "STANDBY mode with   ");
  LCD_DisplayStringLine(Line7, "RTC ON is: 3.6 uA   ");
  LCD_DisplayStringLine(Line8, "Pess SEL to continue");
   
  while(ReadKey() != SEL)
  {
  } 
  
  while(ReadKey() != NOKEY)
  {
  }
  LCD_ClearLine(Line4);
  LCD_ClearLine(Line5);
  LCD_ClearLine(Line6);
  LCD_ClearLine(Line9);
    
  tmp = RTC_GetCounter();

  /* Save the Alarm value in the Backup register */
  BKP_WriteBackupRegister(BKP_DR6, (tmp & 0x0000FFFF));
  BKP_WriteBackupRegister(BKP_DR7, (tmp >> 16));

  Alarm_PreAdjust();

  LCD_DisplayStringLine(Line7, " MCU in STANDBY Mode");
  LCD_DisplayStringLine(Line8, " Wait For RTC Alarm ");

  /* Request to enter STANDBY mode (Wake Up flag is cleared in PWR_EnterSTANDBYMode function) */
  PWR_EnterSTANDBYMode();
}

/**
  * @brief  Sets STOPModeStatus variable.
  * @param  None
  * @retval  None
  */
void Set_STOPModeStatus(void)
{
  STOPModeStatus = 1;
}

/**
  * @brief  Save all GPIOs Configurations.
  * @param  None
  * @retval  None
  */
static void GPIO_SaveConfig(void)
{
  GPIO_InitTypeDef GPIO_InitStructure;
  
  GPIOA_CRL = GPIOA->CRL;
  GPIOA_CRH = GPIOA->CRH;
  
  GPIOB_CRL = GPIOB->CRL;
  GPIOB_CRH = GPIOB->CRH;
  
  GPIOC_CRL = GPIOC->CRL;
  GPIOC_CRH = GPIOC->CRH;
  
  GPIOD_CRL = GPIOD->CRL;
  GPIOD_CRH = GPIOD->CRH;
  
  GPIOE_CRL = GPIOE->CRL;
  GPIOE_CRH = GPIOE->CRH;

  GPIOF_CRL = GPIOF->CRL;
  GPIOF_CRH = GPIOF->CRH;

  GPIOG_CRL = GPIOG->CRL;
  GPIOG_CRH = GPIOG->CRH;
  
  /* Configure all GPIO port pins in Analog Input mode (floating input trigger OFF) */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_All;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AIN;
  GPIO_Init(GPIOA, &GPIO_InitStructure);
  GPIO_Init(GPIOB, &GPIO_InitStructure);
  GPIO_Init(GPIOC, &GPIO_InitStructure);
  GPIO_Init(GPIOD, &GPIO_InitStructure);
  GPIO_Init(GPIOE, &GPIO_InitStructure);  
  GPIO_Init(GPIOF, &GPIO_InitStructure);
  GPIO_Init(GPIOG, &GPIO_InitStructure);
}

/**
  * @brief  Restores all GPIOs Configurations.
  * @param  None
  * @retval  None
  */
static void GPIO_RestoreConfig(void)
{  
  GPIOA->CRL = GPIOA_CRL;
  GPIOA->CRH = GPIOA_CRH;
  
  GPIOB->CRL = GPIOB_CRL;
  GPIOB->CRH = GPIOB_CRH;
  
  GPIOC->CRL = GPIOC_CRL;
  GPIOC->CRH = GPIOC_CRH;
  
  GPIOD->CRL = GPIOD_CRL;
  GPIOD->CRH = GPIOD_CRH;
  
  GPIOE->CRL = GPIOE_CRL;
  GPIOE->CRH = GPIOE_CRH;

  GPIOF->CRL = GPIOF_CRL;
  GPIOF->CRH = GPIOF_CRH; 

  GPIOG->CRL = GPIOG_CRL;
  GPIOG->CRH = GPIOG_CRH;   
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
