/**
  ******************************************************************************
  * @file    calendar.h
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   This file contains all the functions prototypes for the calendar
  *          firmware driver.
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
#ifndef __CALENDAR_H
#define __CALENDAR_H

/* Includes ------------------------------------------------------------------*/
#include "stm32f10x.h"

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported macro ------------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
uint8_t ReadDigit(uint8_t ColBegin, uint8_t CountBegin, uint8_t ValueMax, uint8_t ValueMin) ;
void Calendar_Init(void);
uint32_t Time_Regulate(void);
void Time_Adjust(void);
void Time_Show(void);
void Time_Display(uint32_t TimeVar);
void Date_Regulate(void);
void Date_Adjust(void);
void Date_Display(uint16_t nYear, uint8_t nMonth, uint8_t nDay);
void Date_Show(void);
void Date_Update(void);
uint32_t Alarm_Regulate(void);
void Alarm_Adjust(void);
void Alarm_PreAdjust(void);
void Alarm_Display(uint32_t AlarmVar);
void Alarm_Show(void);

#endif /* __CALENDAR_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
