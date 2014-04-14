/**
  ******************************************************************************
  * @file    hw_config.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   Hardware Configuration & Setup.
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

#include "stm32f10x_it.h"
#include "hw_config.h"
#include "stm3210e_eval_sdio_sd.h"
#include "mass_mal.h"
#include "usb_desc.h"
#include "usb_pwr.h"



/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/

/* Extern variables ----------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
static void RCC_Config(void);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Configures Main system clocks & power
  * @param  None
  * @retval None
  */
void Set_System(void)
{
  /* RCC configuration */
  RCC_Config();

  /* Enable and GPIOD clock */
  USB_Disconnect_Config();

  /* MAL configuration */
  MAL_Config();
}

/**
  * @brief  Configures USB Clock input (48MHz)
  * @param  None
  * @retval None
  */
void Set_USBClock(void)
{
  /* USBCLK = PLLCLK */
  RCC_USBCLKConfig(RCC_USBCLKSource_PLLCLK_1Div5);

  /* Enable USB clock */
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_USB, ENABLE);
}

/**
  * @brief  Power-off system clocks and power while entering suspend mode
  * @param  None
  * @retval None
  */
void Enter_LowPowerMode(void)
{
  /* Set the device state to suspend */
  bDeviceState = SUSPENDED;
}

/**
  * @brief  Restores system clocks and power while exiting suspend mode
  * @param  None
  * @retval None
  */
void Leave_LowPowerMode(void)
{
  DEVICE_INFO *pInfo = &Device_Info;

  /* Set the device state to the correct state */
  if (pInfo->Current_Configuration != 0)
  {
    /* Device configured */
    bDeviceState = CONFIGURED;
  }
  else
  {
    bDeviceState = ATTACHED;
  }

}

/**
  * @brief  Configures the USB interrupts
  * @param  None
  * @retval None
  */
void USB_Interrupts_Config(void)
{
  NVIC_InitTypeDef NVIC_InitStructure;

  NVIC_PriorityGroupConfig(NVIC_PriorityGroup_1);

  NVIC_InitStructure.NVIC_IRQChannel = USB_LP_CAN1_RX0_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

  NVIC_InitStructure.NVIC_IRQChannel = USB_HP_CAN1_TX_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);
  
  NVIC_InitStructure.NVIC_IRQChannel = SDIO_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

}

/**
  * @brief  configure the Read/Write LEDs
  * @param  None
  * @retval None
  */
void Led_Config(void)
{
  /* Configure the LEDs */
  STM_EVAL_LEDInit(LED1);
  STM_EVAL_LEDInit(LED2);  
  STM_EVAL_LEDInit(LED3);
  STM_EVAL_LEDInit(LED4);  
}

/**
  * @brief  Turn ON the Read/Write LEDs.
  * @param  None
  * @retval None
  */
void Led_RW_ON(void)
{
  STM_EVAL_LEDOn(LED3);
}

/**
  * @brief  Turn off the Read/Write LEDs.
  * @param  None
  * @retval None
  */
void Led_RW_OFF(void)
{
  STM_EVAL_LEDOff(LED3);
}

/**
  * @brief  Turn ON USB configured LEDs
  * @param  None
  * @retval None
  */
void USB_Configured_LED(void)
{
  STM_EVAL_LEDOn(LED1);
}

/**
  * @brief  Turn off USB configured LEDs
  * @param  None
  * @retval None
  */
void USB_NotConfigured_LED(void)
{
  STM_EVAL_LEDOff(LED1);
}

/**
  * @brief  Software Connection/Disconnection of USB Cable.
  * @param  None
  * @retval None
  */
void USB_Cable_Config (FunctionalState NewState)
{
  if (NewState != DISABLE)
  {
    GPIO_ResetBits(USB_DISCONNECT, USB_DISCONNECT_PIN);
  }
  else
  {
    GPIO_SetBits(USB_DISCONNECT, USB_DISCONNECT_PIN);
  }
}

/**
  * @brief  Create the serial number string descriptor.
  * @param  None
  * @retval None
  */
void Get_SerialNum(void)
{
  uint32_t Device_Serial0, Device_Serial1, Device_Serial2;

  Device_Serial0 = *(__IO uint32_t*)(0x1FFFF7E8);
  Device_Serial1 = *(__IO uint32_t*)(0x1FFFF7EC);
  Device_Serial2 = *(__IO uint32_t*)(0x1FFFF7F0);

  if (Device_Serial0 != 0)
  {
    MASS_StringSerial[2] = (uint8_t)(Device_Serial0 & 0x000000FF);
    MASS_StringSerial[4] = (uint8_t)((Device_Serial0 & 0x0000FF00) >> 8);
    MASS_StringSerial[6] = (uint8_t)((Device_Serial0 & 0x00FF0000) >> 16);
    MASS_StringSerial[8] = (uint8_t)((Device_Serial0 & 0xFF000000) >> 24);

    MASS_StringSerial[10] = (uint8_t)(Device_Serial1 & 0x000000FF);
    MASS_StringSerial[12] = (uint8_t)((Device_Serial1 & 0x0000FF00) >> 8);
    MASS_StringSerial[14] = (uint8_t)((Device_Serial1 & 0x00FF0000) >> 16);
    MASS_StringSerial[16] = (uint8_t)((Device_Serial1 & 0xFF000000) >> 24);

    MASS_StringSerial[18] = (uint8_t)(Device_Serial2 & 0x000000FF);
    MASS_StringSerial[20] = (uint8_t)((Device_Serial2 & 0x0000FF00) >> 8);
    MASS_StringSerial[22] = (uint8_t)((Device_Serial2 & 0x00FF0000) >> 16);
    MASS_StringSerial[24] = (uint8_t)((Device_Serial2 & 0xFF000000) >> 24);
  }
}

/**
  * @brief  Configures Main system clocks & power
  * @param  None
  * @retval None
  */
static void RCC_Config(void)
{
  /* Setup the microcontroller system. Initialize the Embedded Flash Interface,  
     initialize the PLL and update the SystemFrequency variable. */
  SystemInit();
  
   /* ADCCLK = PCLK2/6 */
   RCC_ADCCLKConfig(RCC_PCLK2_Div6);   
}

/**
  * @brief  MAL_layer configuration
  * @param  None
  * @retval None
  */
void MAL_Config(void)
{
  MAL_Init(0);

  /* Enable the FSMC Clock */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  MAL_Init(1);
}

/**
  * @brief  Disconnect pin configuration
  * @param  None
  * @retval None
  */
void USB_Disconnect_Config(void)
{
  GPIO_InitTypeDef GPIO_InitStructure;

  /* Enable USB_DISCONNECT GPIO clock */
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIO_DISCONNECT, ENABLE);

  /* USB_DISCONNECT_PIN used as USB pull-up */
  GPIO_InitStructure.GPIO_Pin = USB_DISCONNECT_PIN;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_OD;
  GPIO_Init(USB_DISCONNECT, &GPIO_InitStructure);
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
