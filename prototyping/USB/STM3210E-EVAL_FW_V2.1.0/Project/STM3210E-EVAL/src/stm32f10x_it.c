/**
  ******************************************************************************
  * @file    stm32f10x_it.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   Main Interrupt Service Routines.
  *          This file provides template for all exceptions handler
  *          and peripherals interrupt service routine.
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
#include "stm3210e_eval_sdio_sd.h"

/** @addtogroup STM32F10x_StdPeriph_Template
  * @{
  */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
static __IO uint32_t Index = 0;
static __IO uint32_t AlarmStatus = 0;
static __IO uint32_t LedCounter = 0;
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/******************************************************************************/
/*            Cortex-M3 Processor Exceptions Handlers                         */
/******************************************************************************/

/**
  * @brief  This function handles NMI exception.
  * @param  None
  * @retval None
  */
void NMI_Handler(void)
{
uint32_t tmp = 318, index = 0;

  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

  /* Disable LCD Window mode */
  LCD_WindowModeDisable(); 

  /* If HSE is not detected at program startup or HSE clock failed during program execution */
  if((Get_HSEStartUpStatus() == ERROR) || (RCC_GetITStatus(RCC_IT_CSS) != RESET))
  { 
    /* Clear the LCD */
    LCD_Clear(White);
    /* Set the LCD Back Color */
    LCD_SetBackColor(Blue);

    /* Set the LCD Text Color */
    LCD_SetTextColor(White);

    /* Display " No Clock Detected  " message */
    LCD_DisplayStringLine(Line0, "No HSE Clock        ");
    LCD_DisplayStringLine(Line1, "Detected. STANDBY   ");
    LCD_DisplayStringLine(Line2, "mode in few seconds.");
    
    LCD_DisplayStringLine(Line5, "If HSE Clock         ");
    LCD_DisplayStringLine(Line6, "recovers before the  ");
    LCD_DisplayStringLine(Line7, "time out, a System   ");
    LCD_DisplayStringLine(Line8, "Reset is generated.  ");
    LCD_ClearLine(Line9);
    /* Clear Clock Security System interrupt pending bit */
    RCC_ClearITPendingBit(RCC_IT_CSS);
    
    STM_EVAL_LEDOn(LED1);
    STM_EVAL_LEDOn(LED2);
    STM_EVAL_LEDOn(LED3);
    STM_EVAL_LEDOn(LED4);
    
    /* Enable HSE */
    RCC_HSEConfig(RCC_HSE_ON);
    LCD_ClearLine(Line4);
    /* Set the Back Color */
    LCD_SetBackColor(White);
    /* Set the Text Color */
    LCD_SetTextColor(Red);
    LCD_DrawRect(71, 319, 25, 320);
    LCD_SetBackColor(Green); 
    LCD_SetTextColor(White);

    /* Wait till HSE is ready */
    while(RCC_GetFlagStatus(RCC_FLAG_HSERDY) == RESET)
    {
      if(index == 0x3FFFF)
      {
        LCD_DisplayChar(Line3, tmp, 0x20);
        tmp -= 16;
        index = 0;
      }
      index++;
      /* Enters the system in STANDBY mode */
      if(tmp < 16)
      {
        LCD_SetBackColor(Blue);
        LCD_ClearLine(Line3);
        LCD_ClearLine(Line4);
        LCD_ClearLine(Line5);
        LCD_ClearLine(Line6);
        LCD_DisplayStringLine(Line7, " MCU in STANDBY Mode"); 
        LCD_DisplayStringLine(Line8, "To exit press Wakeup");
        /* Request to enter STANDBY mode */
        PWR_EnterSTANDBYMode();
      }
    }
  
    /* Generate a system reset */  
    NVIC_SystemReset();
  }
}

/**
  * @brief  This function handles Hard Fault exception.
  * @param  None
  * @retval None
  */
void HardFault_Handler(void)
{
  /* Go to infinite loop when Hard Fault exception occurs */
  while (1)
  {
  }
}

/**
  * @brief  This function handles Memory Manage exception.
  * @param  None
  * @retval None
  */
void MemManage_Handler(void)
{
  /* Go to infinite loop when Memory Manage exception occurs */
  while (1)
  {
  }
}

/**
  * @brief  This function handles Bus Fault exception.
  * @param  None
  * @retval None
  */
void BusFault_Handler(void)
{
  /* Go to infinite loop when Bus Fault exception occurs */
  while (1)
  {
  }
}

/**
  * @brief  This function handles Usage Fault exception.
  * @param  None
  * @retval None
  */
void UsageFault_Handler(void)
{
  /* Go to infinite loop when Usage Fault exception occurs */
  while (1)
  {
  }
}

/**
  * @brief  This function handles SVCall exception.
  * @param  None
  * @retval None
  */
void SVC_Handler(void)
{
}

/**
  * @brief  This function handles Debug Monitor exception.
  * @param  None
  * @retval None
  */
void DebugMon_Handler(void)
{
}

/**
  * @brief  This function handles PendSVC exception.
  * @param  None
  * @retval None
  */
void PendSV_Handler(void)
{
}

/**
  * @brief  This function handles SysTick Handler.
  * @param  None
  * @retval None
  */
void SysTick_Handler(void)
{
  /* Decrement the TimingDelay variable */
  Decrement_TimingDelay();
}

/******************************************************************************/
/*                 STM32F10x Peripherals Interrupt Handlers                   */
/*  Add here the Interrupt Handler for the used peripheral(s) (PPP), for the  */
/*  available peripheral interrupt handler's name please refer to the startup */
/*  file (startup_stm32f10x_xx.s).                                            */
/******************************************************************************/

/**
  * @brief  This function handles PPP interrupt request.
  * @param  None
  * @retval None
  */
/*void PPP_IRQHandler(void)
{
}*/

/**
  * @}
  */ 

/**
  * @brief  This function handles RTC global interrupt request.
  * @param  None
  * @retval None
  */
void RTC_IRQHandler(void)
{
  /* If counter is equal to 86339: one day was elapsed */
  if((RTC_GetCounter()/3600 == 23)&&(((RTC_GetCounter()%3600)/60) == 59)&&
     (((RTC_GetCounter()%3600)%60) == 59)) /* 23*3600 + 59*60 + 59 = 86339 */
  {
    /* Wait until last write operation on RTC registers has finished */
    RTC_WaitForLastTask();
    /* Reset counter value */
    RTC_SetCounter(0x0);
    /* Wait until last write operation on RTC registers has finished */
    RTC_WaitForLastTask();

    /* Increment the date */
    Date_Update();
  }
  /* Clear the RTC Second Interrupt pending bit */  
  RTC_ClearITPendingBit(RTC_IT_SEC);
}

/**
  * @brief  This function handles External interrupt Line 3 request.
  * @param  None
  * @retval None
  */
void EXTI3_IRQHandler(void)
{
  if(EXTI_GetITStatus(EXTI_Line3) != RESET)
  {
    DownFunc();  
    /* Clear the EXTI Line 3 */
    EXTI_ClearITPendingBit(EXTI_Line3);
  }
}

/**
  * @brief  This function handles USB High Priority or CAN TX interrupt request.
  * @param  None
  * @retval None
  */
void USB_HP_CAN1_TX_IRQHandler(void)
{
  CTR_HP();
}

/**
  * @brief  This function handles USB Low Priority or CAN RX0 interrupt request.
  * @param  None
  * @retval None
  */
void USB_LP_CAN1_RX0_IRQHandler(void)
{
  USB_Istr();
}

/**
  * @brief  This function handles External lines 9 to 5 interrupt request.
  * @param  None
  * @retval None
  */
void EXTI9_5_IRQHandler(void)
{
  if(Get_SmartCardStatus() == 0)
  { 
    if(EXTI_GetITStatus(EXTI_Line8) != RESET)
    {
      /* Clear the EXTI Line 8 */  
      EXTI_ClearITPendingBit(EXTI_Line8);
    }
    if(EXTI_GetITStatus(EXTI_Line7) != RESET)
    {
      /* SEL function */
      Set_SELStatus();
      /* Clear the EXTI Line 7 */  
      EXTI_ClearITPendingBit(EXTI_Line7);
    }
  }
  else if(Get_SmartCardStatus() == 1)
  {
    if(EXTI_GetITStatus(SC_EXTI) != RESET)
    {
      /* Clear SC EXTIT Line Pending Bit */
      EXTI_ClearITPendingBit(SC_EXTI);

      /* Smartcard detected */
      Set_CardInserted();

      /* Power ON the card */
      SC_PowerCmd(ENABLE);

      /* Reset the card */
      SC_Reset(Bit_RESET);
    }
  }
  if(EXTI_GetITStatus(EXTI_Line8) != RESET)
  {
    /* Clear the EXTI Line 8 */
    EXTI_ClearITPendingBit(EXTI_Line8);
  }
}

/**
  * @brief  This function handles TIM1 overflow and update  interrupt request.
  * @param  None
  * @retval None
  */
void TIM1_UP_IRQHandler(void)
{
  /* Clear the TIM1 Update pending bit */
  TIM_ClearITPendingBit(TIM1, TIM_IT_Update);

  if(AlarmStatus == 1)
  {
    if((LedCounter & 0x01) == 0) 
    {
      STM_EVAL_LEDOn(LED1);
      STM_EVAL_LEDOn(LED2);
      STM_EVAL_LEDOn(LED3);
      STM_EVAL_LEDOn(LED4);
    }
    else if ((LedCounter & 0x01) == 0x01)
    {
      STM_EVAL_LEDOff(LED1);
      STM_EVAL_LEDOff(LED2);
      STM_EVAL_LEDOff(LED3);
      STM_EVAL_LEDOff(LED4);
    }

    LedCounter++;

    if(LedCounter == 300)
    {
      AlarmStatus = 0;
      LedCounter = 0;
    }
  }
  else
  {
    /* If LedShowStatus is TRUE: enable leds toggling */
    if(Get_LedShowStatus() != 0)
    {
      switch(Index)
      {
        /* LD1 turned on, LD4 turned off */
      case 0:
        {
          STM_EVAL_LEDOff(LED1);
          STM_EVAL_LEDOn(LED4);
          Index++;
          break;
        }
        /* LD2 turned on, LD1 turned off */
      case 1:
        {
          STM_EVAL_LEDOff(LED2);
          STM_EVAL_LEDOn(LED1);
          Index++;
          break;
        }
        /* LD3 turned on, LD2 turned off */
      case 2:
        {
          STM_EVAL_LEDOff(LED3);
          STM_EVAL_LEDOn(LED2);
          Index++;
          break;
        }
        /* LD4 turned on, LD3 turned off */
      case 3:
        {
          STM_EVAL_LEDOff(LED4);
          STM_EVAL_LEDOn(LED3);
          Index++;
          break;
        }
      default:
        break;
      }
      /* Reset Index to replay leds switch on sequence  */
      if(Index == 4)
      {
        Index = 0;
      }
    }
  }
}

/**
  * @brief  This function handles SPI2 global interrupt request.
  * @param  None
  * @retval None
  */
void SPI2_IRQHandler(void)
{
  if ((SPI_I2S_GetITStatus(SPI2, SPI_I2S_IT_TXE) == SET))
  {
    /* Send data on the SPI2 and Check the current commands */
    I2S_CODEC_DataTransfer();
  }
}

/**
  * @brief  This function handles USART3 global interrupt request.
  * @param  None
  * @retval None
  */
void USART3_IRQHandler(void)
{
  /* If a Frame error is signaled by the card */
  if(USART_GetITStatus(USART3, USART_IT_FE) != RESET)
  {
    /* Clear the USART3 Frame error pending bit */
    USART_ClearITPendingBit(USART3, USART_IT_FE);
    USART_ReceiveData(USART3);

    /* Resend the byte that failed to be received (by the Smartcard) correctly */
    SC_ParityErrorHandler();
  }
  
  /* If the USART3 detects a parity error */
  if(USART_GetITStatus(USART3, USART_IT_PE) != RESET)
  {
    while(USART_GetFlagStatus(USART3, USART_FLAG_RXNE) == RESET)
    {
    }
    /* Clear the USART3 Parity error pending bit */
    USART_ClearITPendingBit(USART3, USART_IT_PE);
    USART_ReceiveData(USART3);
  }
  /* If a Overrun error is signaled by the card */
  if(USART_GetITStatus(USART3, USART_IT_ORE) != RESET)
  {
    /* Clear the USART3 Frame error pending bit */
    USART_ClearITPendingBit(USART3, USART_IT_ORE);
    USART_ReceiveData(USART3);
  }
  /* If a Noise error is signaled by the card */
  if(USART_GetITStatus(USART3, USART_IT_NE) != RESET)
  {
    /* Clear the USART3 Frame error pending bit */
    USART_ClearITPendingBit(USART3, USART_IT_NE);
    USART_ReceiveData(USART3);
  }
}

/**
  * @brief  This function handles External lines 15 to 10 interrupt request.
  * @param  None
  * @retval None
  */
void EXTI15_10_IRQHandler(void)
{
  if(EXTI_GetITStatus(EXTI_Line15) != RESET)
  {
    UpFunc();
    /* Clear the EXTI Line 15 */  
    EXTI_ClearITPendingBit(EXTI_Line15);
  }
 
}

/**
  * @brief  This function handles RTC Alarm  interrupt request.
  * @param  None
  * @retval None
  */
void RTCAlarm_IRQHandler(void)
{
  /* Clear the Alarm Pending Bit */
  RTC_ClearITPendingBit(RTC_IT_ALR);
  
  AlarmStatus = 1;
  Set_STOPModeStatus();

  /* Clear the EXTI Line 17/ */  
  EXTI_ClearITPendingBit(EXTI_Line17);
}

/**
  * @brief  This function handles SDIO global  interrupt request.
  * @param  None
  * @retval None
  */
void SDIO_IRQHandler(void)
{
  /* Process All SDIO Interrupt Sources */
  SD_ProcessIRQSrc();
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
