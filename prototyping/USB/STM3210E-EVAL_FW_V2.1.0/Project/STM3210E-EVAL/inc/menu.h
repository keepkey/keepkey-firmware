/**
  ******************************************************************************
  * @file    menu.h
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   This file contains all the functions prototypes for the menu
  *          navigation firmware driver.
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

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MENU_H
#define __MENU_H

/* Includes ------------------------------------------------------------------*/
#include "stm32f10x.h"
#include "stm3210e_eval_fsmc_nor.h"

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
#define  MAX_MENU_LEVELS 4
#define  NOKEY  0
#define  SEL    1
#define  RIGHT  2
#define  LEFT   3
#define  UP     4
#define  DOWN   5
#define  KEY    6

#define ALARM_ICON 0x64FE0F54
#define USB_ICON   0x64FE8F96
#define WATCH_ICON 0x64FF0FD8
#define ST_LOGO    0x64F7FBFA
#define HELP       0x64FA543C
#define TSENSOR	   0x64FD8E4C

/* Module private variables --------------------------------------------------*/
/* Exported macro ------------------------------------------------------------*/
#define countof(a) (sizeof(a) / sizeof(*(a)))

/* Private functions ---------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
void Menu_Init(void);
void DisplayMenu(void);
void SelFunc(void);
void UpFunc(void);
void DownFunc(void);
void ReturnFunc(void);
uint8_t ReadKey(void);
void IdleFunc(void);
void DisplayIcons(void);
void ShowMenuIcons(void);
void STM32Intro(void);
void HelpFunc(void);
void AboutFunc(void);
void LCD_NORDisplay(uint32_t address);
void Thermometer_Temperature(void);
void STM32BannerFunc(void);
void ProductPres(void);
uint32_t CheckBitmapFiles(void);
void SmartCard_Start(void);
void STM32BannerSpeedFunc(void);
uint32_t Get_SmartCardStatus(void);
void Set_CardInserted(void);

#endif /* __MENU_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
