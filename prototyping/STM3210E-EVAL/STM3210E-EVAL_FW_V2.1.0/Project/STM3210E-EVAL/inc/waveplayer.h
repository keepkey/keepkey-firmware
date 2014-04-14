/**
  ******************************************************************************
  * @file    waveplayer.h
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   This file contains all the functions prototypes for the waveplayer
  *          driver.
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
#ifndef __WAVEPLAYER_H
#define __WAVEPLAYER_H

/* Includes ------------------------------------------------------------------*/
#include "stm32f10x.h"
#include "i2s_codec.h"

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Audio file location */
#define AUDIO_FILE_ADDRESS  0x64060000

/* LCD display update parameters */
#define STOP        0x10000000
#define PLAY        0x01000000
#define PAUSE       0x00100000 
#define VOL         0x00010000
#define PROGRESS    0x00001000
#define FRWD        0x00000100
#define ALL         0x11110100

/* Exported macro ------------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
void WavePlayer_StartSpeaker (void);
void LCD_Update(uint32_t Status);
void LCD_DisplayError(uint32_t err);
void I2S_CODEC_LCDConfig(void);

#endif /* __WAVEPLAYER_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
