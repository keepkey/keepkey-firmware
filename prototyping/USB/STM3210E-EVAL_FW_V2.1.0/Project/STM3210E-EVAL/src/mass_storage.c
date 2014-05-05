/**
  ******************************************************************************
  * @file    mass_storage.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   This file provides a set of functions needed to manage the
  *          communication between the STM32F10x USB and the SD Card and NAND Flash.
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
#include "usb_lib.h"
#include "hw_config.h"
#include "usb_lib.h"
#include "usb_istr.h"
#include "stm3210e_eval_sdio_sd.h"
#include "stm3210e_eval_fsmc_nand.h"
#include "nand_if.h"

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Initializes the peripherals used by the mass storage driver.
  * @param  None
  * @retval None
  */
void Mass_Storage_Init(void)
{
  /* Disable the Pull-Up*/
  USB_Cable_Config(DISABLE);

}

/**
  * @brief  Starts the mass storage demo.
  * @param  None
  * @retval None
  */
void Mass_Storage_Start (void)
{
  NVIC_InitTypeDef NVIC_InitStructure;

  /* Disble the JoyStick interrupts */
  IntExtOnOffConfig(DISABLE);


  while(ReadKey() != NOKEY)
  {
  }

  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  /* Clear the LCD screen */
  LCD_Clear(White);

  LCD_SetDisplayWindow(160, 223, 128, 128);
 
  LCD_NORDisplay(USB_ICON);
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  /* Disable LCD Window mode */
  LCD_WindowModeDisable();
  
  /* Set the Back Color */
  LCD_SetBackColor(Blue);
  /* Set the Text Color */
  LCD_SetTextColor(White); 

  
  /* Display the "  Plug the USB   " message */
  LCD_DisplayStringLine(Line8, " Plug the USB Cable ");
  LCD_DisplayStringLine(Line9, "Exit:  Push JoyStick");
    
  /* Enable and GPIOD clock */
  USB_Disconnect_Config();
  
  /* MAL configuration */
  MAL_Config();

  Set_USBClock();

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

  USB_Init();

  while (bDeviceState != CONFIGURED)
  {
    if(ReadKey() != NOKEY)
    {
      PowerOff();
      LCD_Clear(White);
      DisplayMenu();
      IntExtOnOffConfig(ENABLE);
      return;
    }
  }

  LCD_ClearLine(Line9);
  /* Display the "To stop Press SEL" message */
  LCD_DisplayStringLine(Line8, "  To stop Press SEL ");

  /* Loop until SEL key pressed */
  while(ReadKey() != SEL)
  {
  }

  PowerOff();
  
  LCD_Clear(White);
  DisplayMenu();
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Erases the NAND Flash Content.
  * @param  None
  * @retval None
  */
void Mass_Storage_Recovery (void)
{
  /* Disble the JoyStick interrupts */
  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }

  LCD_Clear(White);

  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

  /* Set the Back Color */
  LCD_SetBackColor(Blue);
  /* Set the Text Color */
  LCD_SetTextColor(White); 

  LCD_DisplayStringLine(Line4, " Erase NAND Content ");
  LCD_DisplayStringLine(Line5, "Please wait...      ");
 
  /* FSMC Initialization */
  NAND_Init();

  NAND_Format();

  /* Display the "To stop Press SEL" message */
  LCD_DisplayStringLine(Line4, "     NAND Erased    ");
  LCD_DisplayStringLine(Line5, "  To exit Press SEL ");

  /* Loop until SEL key pressed */
  while(ReadKey() != SEL)
  {
  }
  
  LCD_Clear(White);
  DisplayMenu();
  IntExtOnOffConfig(ENABLE);
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
