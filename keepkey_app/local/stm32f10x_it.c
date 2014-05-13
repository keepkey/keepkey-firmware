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
  /* Clear the RTC Second Interrupt pending bit */  
  RTC_ClearITPendingBit(RTC_IT_SEC);
}

/**
  * @brief  This function handles USB High Priority or CAN TX interrupt request.
  * @param  None
  * @retval None
  */
void USB_HP_CAN1_TX_IRQHandler(void)
{
}

/**
  * @brief  This function handles USB Low Priority or CAN RX0 interrupt request.
  * @param  None
  * @retval None
  */
void USB_LP_CAN1_RX0_IRQHandler(void)
{
}


/**
  * @brief  This function handles TIM1 overflow and update  interrupt request.
  * @param  None
  * @retval None
  */
void TIM1_UP_IRQHandler(void)
{
}

/**
  * @brief  This function handles SPI2 global interrupt request.
  * @param  None
  * @retval None
  */
void SPI2_IRQHandler(void)
{
}

/**
  * @brief  This function handles USART3 global interrupt request.
  * @param  None
  * @retval None
  */
void USART3_IRQHandler(void)
{
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
}


void 
WWDG_IRQHandler(
    void
)
{
  return;
}

#if 0
/**
  * @brief  This function handles External lines 9 to 5 interrupt request.
  * @param  None
  * @retval None
  */
void EXTI9_5_IRQHandler(void)
{
  if(EXTI_GetITStatus(EXTI_Line8) != RESET)
  {
    /* Clear the EXTI Line 8 */
    EXTI_ClearITPendingBit(EXTI_Line8);
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
    /* Clear the EXTI Line 15 */  
    EXTI_ClearITPendingBit(EXTI_Line15);
  }
 
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
    /* Clear the EXTI Line 3 */
    EXTI_ClearITPendingBit(EXTI_Line3);
  }
}
#endif


/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
