/**
  ******************************************************************************
  * @file    main.h
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   Header for main.c module.
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
#ifndef __MAIN_H
#define __MAIN_H

/* Includes ------------------------------------------------------------------*/
#include "stm3210e_eval_lcd.h"
#include "stm32f10x_it.h"
#include "menu.h"
#include "calendar.h"
#include "mass_storage.h"
#include "waveplayer.h"
#include "lowpower.h"
#include "stm3210e_eval_i2c_tsensor.h"
#include "smartcard.h"

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported macro ------------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
void Demo_Init(void);
void InterruptConfig(void);
void SysTick_Configuration(void);
void IntExtOnOffConfig(FunctionalState NewState);
void GPIO_Config(void);
void Delay(__IO uint32_t nCount);
uint32_t DelayJoyStick(__IO uint32_t nTime);
void Decrement_TimingDelay(void);
void Set_SELStatus(void);
void LedShow_Init(void);
void LedShow(FunctionalState NewState);
uint32_t Get_LedShowStatus(void);
void CheckBitmapFilesStatus(void);
ErrorStatus Get_HSEStartUpStatus(void);

#endif /* __MAIN_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
