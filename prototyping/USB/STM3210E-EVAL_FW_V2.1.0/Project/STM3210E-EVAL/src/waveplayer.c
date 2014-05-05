/**
  ******************************************************************************
  * @file    waveplayer.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   Wave Player driver source file.
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
#define REPLAY  3

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
uint8_t DemoTitle[20] = "STM32 I2S Codec Demo"; 

uint8_t CmdTitle0[20] = "  Control Buttons:  "; 

uint8_t CmdTitle1Playing[20] = "KEY>Pause  UP  >Vol+";

uint8_t CmdTitle2Playing[20] = "SEL>Stop   DOWN>Vol-";

uint8_t CmdTitle1Paused[20] =  "KEY>Play   UP  >Spkr";

uint8_t CmdTitle2Paused[20] =  "SEL>Stop   DOWN>Head";

uint8_t CmdTitle1Stopped[20] = "    UP > Speaker    "; 

uint8_t CmdTitle2Stopped[20] = "  DOWN > Headphone  "; 

uint8_t StatusTitleStopped[20] = "      Stopped       ";

uint8_t StatusTitlePlaying[20] = "      Playing       ";

uint8_t StatusTitlePaused[20] = "       Paused       ";

uint8_t i2cerr[20] =  "ERROR:I2C com. ->RST";
uint8_t memerr[20] =  "ERROR: Memory  ->RST";
uint8_t fileerr[20] = "ERROR: No Wave File ";

static uint8_t previoustmp = 50;

/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Starts the wave player application.
  * @param  None
  * @retval None
  */
void WavePlayer_StartSpeaker(void)
{
  uint8_t MyKey = 0;
  uint32_t err = 0, Counter = 0x0;

  LCD_Clear(White);

  /* Disable the JoyStick interrupts */
  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }  

  /* Display the welcome screen and the commands */
  LCD_Update(ALL);

  /* Choose number of repetitions: 0 => infinite repetitions */
  I2S_CODEC_ReplayConfig(0);
  I2S_CODEC_Init(OutputDevice_SPEAKER, AUDIO_FILE_ADDRESS);

  /* Endless loop */
  while(1)
  {
    /* Check which key is pressed */
    MyKey = ReadKey();
    
    if(Counter == 0)
    { 
      /* Mask All Interrupts */
      __disable_irq();
      /* Update the displayed progression information */
      LCD_Update(PROGRESS);
      Counter = 0x5FFFF;
      /* Disable mask of all interrupts */
        __enable_irq();
    }
    Counter--;
    /* If "UP" pushbutton is pressed */
    if(MyKey == UP)
    {
      /* Mask All Interrupts */
       __disable_irq();
      /* Check if the Codec is PLAYING audio file */
      if (GetVar_AudioPlayStatus() == AudioPlayStatus_PLAYING)
      {
        I2S_CODEC_ControlVolume(VolumeDirection_HIGH, VOLStep);

        /* Update the display information */
        LCD_Update(VOL);
      }
      /* UP bottomn pushed in PAUSE mode => Enable the Speaker device output ---*/
      else
      {
        /* Update the display information */
        LCD_Update(PLAY);

        /* Configure the Speaker as output and reinitialize all devices */
        err = I2S_CODEC_SpeakerHeadphoneSwap(OutputDevice_SPEAKER, AUDIO_FILE_ADDRESS);
  
        /* Error message display if failure */
        if (err != 0)
        {
          LCD_DisplayError(err);

          /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
          RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

          /* Clear the LCD */
          LCD_Clear(White);

          /* Display the previous menu */
          DisplayMenu();

          /* Disable mask of all interrupts */
          __enable_irq();
          /* Enable the JoyStick interrupts */
          IntExtOnOffConfig(ENABLE); 
          return; 
        }      
      } 
      /* Disable mask of all interrupts */
      __enable_irq();
    }

    /* If "DOWN" pushbutton is pressed */
    if(MyKey == DOWN)
    {
      /* Mask All Interrupts */
     __disable_irq();
      /* If the Codec is PLAYING => Decrease Volume*/
      if (GetVar_AudioPlayStatus() == AudioPlayStatus_PLAYING)
      {
        /* Increase the audio codec digital volume */
        I2S_CODEC_ControlVolume(VolumeDirection_LOW, VOLStep);

        /* Update the LCD display */ 
        LCD_Update(VOL); 
      }
      else /* If the Codec is PAUSED => Headphone Enable */
      {
        /* Update the LCD display */ 
        LCD_Update(PLAY);
      
        /* Enable the Headphone output and reinitialize all devices */ 
        err = I2S_CODEC_SpeakerHeadphoneSwap(OutputDevice_HEADPHONE, AUDIO_FILE_ADDRESS);

        /* Error message display if failure */
        if (err != 0)
        {
          LCD_DisplayError(err);

          /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
          RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

          /* Clear the LCD */
          LCD_Clear(White);

          /* Display the previous menu */
          DisplayMenu();

          /* Disable mask of all interrupts */
          __enable_irq();
          /* Enable the JoyStick interrupts */
          IntExtOnOffConfig(ENABLE); 
          return; 
        }  
      }
      /* Disable mask of all interrupts */
      __enable_irq();
    }

    /* If "RIGHT" pushbutton is pressed */
    if(MyKey == RIGHT)
    {
      /* Mask All Interrupts */
    __disable_irq();
      /* Check if the Codec is PLAYING audio file */
      if (GetVar_AudioPlayStatus() == AudioPlayStatus_PLAYING)
      {
        I2S_CODEC_ForwardPlay(STEP_FORWARD); 
        /* Update the display information */
        LCD_Update(FRWD); 
      }
      /* Disable mask of all interrupts */
      __enable_irq();
    }
    /* If "LEFT" pushbutton is pressed */
    if(MyKey == LEFT)
    {
      /* Mask All Interrupts */
     __disable_irq();
      /* Check if the Codec is PLAYING audio file */
      if (GetVar_AudioPlayStatus() == AudioPlayStatus_PLAYING)
      {
        I2S_CODEC_RewindPlay(STEP_BACK);
        /* Update the display information */
        LCD_Update(FRWD);  
      } 
      /* Disable mask of all interrupts */
      __enable_irq();
    }

    /* If "SEL" pushbutton is pressed */
    if(MyKey == SEL)
    {
      /* Mask All Interrupts */
       __disable_irq();

      /* Update the display information */
      LCD_Update(STOP);

      /* Command the Stop of the current audio stream */
      SetVar_AudioPlayStatus(AudioPlayStatus_STOPPED);

      /* Disable mask of all interrupts */
      __enable_irq();

      I2S_CODEC_Stop();
      SPI_I2S_ITConfig(SPI2, SPI_I2S_IT_TXE, DISABLE);

      /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
      RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

      /* Clear the LCD */
      LCD_Clear(White);

      /* Display the previous menu */
      DisplayMenu();
      /* Enable the JoyStick interrupts */
      IntExtOnOffConfig(ENABLE); 
      return;     
    }
    /* If "KEY" pushbutton is pressed */
    if(MyKey == KEY)
    {
      /* Mask All Interrupts */
       __disable_irq();

      /* If the Codec is Playing => PAUSE */
      if (GetVar_AudioPlayStatus() == AudioPlayStatus_PLAYING)
      {
        /* Update the display information */
        LCD_Update(PAUSE);

        /* Command the Pause of the current stream */
        SetVar_AudioPlayStatus(AudioPlayStatus_PAUSED);
      }

      /* If the Codec is PAUSED => Resume PLAYING */
      else if (GetVar_AudioPlayStatus() == AudioPlayStatus_PAUSED)
      {
        /* Update the LCD display */ 
        LCD_Update(PLAY); 

        /* Start playing from the last saved position */
        I2S_CODEC_Play(GetVar_AudioDataIndex());
      }
      /* If the Codec is STOPPED => PLAY from the file start address */
      else if (GetVar_AudioPlayStatus() == AudioPlayStatus_STOPPED)
      {
        /* Update the display information */
        LCD_Update(PLAY);

        /* Initialize all devices w/choosen parameters */
        err = I2S_CODEC_Init(GetVar_CurrentOutputDevice(), AUDIO_FILE_ADDRESS);
  
        /* Error message display if failure */
        if (err != 0)
        {
          LCD_DisplayError(err);

          /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
          RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

          /* Clear the LCD */
          LCD_Clear(White);

          /* Display the previous menu */
          DisplayMenu();

          /* Disable mask of all interrupts */
          __enable_irq();

          /* Enable the JoyStick interrupts */
          IntExtOnOffConfig(ENABLE); 
          return; 
        }  
          
        /* Enable Playing the audio file */
        I2S_CODEC_Play(GetVar_DataStartAddr());
      }
      /* Disable mask of all interrupts */
      __enable_irq();
    }
  }
}

/**
  * @brief  Controls the wave player application LCD display messages.
  * @param  None
  * @retval None
  */
void LCD_Update(uint32_t Status)
{
  uint8_t tmp = 0;
  uint32_t counter = 0;

  /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

  switch (Status)
  {
   case PROGRESS:
         tmp = (uint8_t) ((uint32_t)((GetVar_AudioDataIndex()) * 100) / GetVar_AudioDataLength());
         if (tmp == 0)
         { 
           LCD_SetTextColor(Magenta);
           LCD_ClearLine(Line8);
           LCD_DrawRect(Line8, 310, 16, 300);
         }
         else
         {
           LCD_SetTextColor(Magenta);
           LCD_DrawLine(Line8, 310 - (tmp * 3), 16, Vertical);
         }         
         break;
   case FRWD:
         tmp = (uint8_t) ((uint32_t)((GetVar_AudioDataIndex()) * 100) / GetVar_AudioDataLength());

         LCD_SetTextColor(Magenta);
         LCD_ClearLine(Line8);
         LCD_DrawRect(Line8, 310, 16, 300);
         LCD_SetTextColor(Magenta);

         for (counter = 0; counter <= tmp; counter++)
         {
           LCD_DrawLine(Line8, 310 - (counter * 3), 16, Vertical);
         }          
         break;
   case STOP:
         /* Display the stopped status menu */ 
         LCD_SetTextColor(White); 
         LCD_DisplayStringLine(Line3, CmdTitle1Stopped);
         LCD_DisplayStringLine(Line4, CmdTitle2Stopped);
         LCD_SetTextColor(Red);
         LCD_DisplayStringLine(Line6, StatusTitleStopped);
         LCD_ClearLine(Line9);
         LCD_SetTextColor(Black);
         LCD_DisplayChar(Line9, 250, 'v'); 
         LCD_DisplayChar(Line9, 235, 'o'); 
         LCD_DisplayChar(Line9, 220, 'l'); 
         LCD_DisplayChar(Line9, 200, '-'); 
         LCD_DisplayChar(Line9, 85, '+'); 
         LCD_DrawRect(Line9 + 8, 185, 10, 100); 
         break; 
   case PAUSE: 
         /* Display the paused status menu */ 
         LCD_SetTextColor(White);
         LCD_DisplayStringLine(Line3, CmdTitle1Paused);
         LCD_DisplayStringLine(Line4, CmdTitle2Paused);
         LCD_SetTextColor(Red);
         LCD_DisplayStringLine(Line6, StatusTitlePaused);
         break;
   case PLAY:
         /* Display the Titles */   
         LCD_SetTextColor(Black);
         LCD_DisplayStringLine(Line0, DemoTitle);
         LCD_DisplayStringLine(Line2, CmdTitle0); 

         /* Display the Playing status menu */ 
         LCD_SetTextColor(White);
         LCD_DisplayStringLine(Line3, CmdTitle1Playing);
         LCD_DisplayStringLine(Line4, CmdTitle2Playing);
         LCD_SetTextColor(Red);
         LCD_DisplayStringLine(Line6, StatusTitlePlaying);
         LCD_ClearLine(Line9);
         LCD_SetTextColor(Black);
         LCD_DisplayChar(Line9, 250, 'v'); 
         LCD_DisplayChar(Line9, 235, 'o'); 
         LCD_DisplayChar(Line9, 220, 'l'); 
         LCD_DisplayChar(Line9, 200, '-'); 
         LCD_DisplayChar(Line9, 85, '+'); 
         LCD_DrawRect(Line9 + 8, 185, 10, 100); 
         break;
   case ALL: 
         I2S_CODEC_LCDConfig();
         /* Display the stopped status menu */ 
         LCD_SetTextColor(White); 
         LCD_DisplayStringLine(Line3, CmdTitle1Stopped);
         LCD_DisplayStringLine(Line4, CmdTitle2Stopped);
         LCD_SetTextColor(Red);
         LCD_DisplayStringLine(Line6, StatusTitleStopped);
         LCD_ClearLine(Line9);
         LCD_SetTextColor(Black);
         LCD_DisplayChar(Line9, 250, 'v'); 
         LCD_DisplayChar(Line9, 235, 'o'); 
         LCD_DisplayChar(Line9, 220, 'l'); 
         LCD_DisplayChar(Line9, 200, '-'); 
         LCD_DisplayChar(Line9, 85, '+'); 
         LCD_DrawRect(Line9 + 8, 185, 10, 100); 
         break;
  }
  /* Update the volume bar in all cases except when progress bar is to be apdated */
  if (Status != PROGRESS)
  {
    /* Compute the current volume percentage */
    tmp = (uint8_t) ((uint16_t)((0xFF - GetVar_CurrentVolume()) * 100) / 0xFF) ;
 
    /* Clear the previuos volume bar */
    LCD_SetTextColor(Blue);
    LCD_DrawLine(Line9 + 10, 185 - previoustmp , 8, Vertical);
    LCD_DrawLine(Line9 + 10, 185 - previoustmp + 1 , 8, Vertical);    
 
    /* Draw the new volume bar */
    LCD_SetTextColor(Red);
    LCD_DrawLine(Line9 + 10, 185 - tmp , 8, Vertical);
    LCD_DrawLine(Line9 + 10, 185 - tmp + 1 , 8, Vertical);
 
    /* save the current position */
    previoustmp = tmp;
  }
  /* Disable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);
}

/**
  * @brief  Displays error message on the LCD screen and prompt user to reset 
  *         the application.
  * @param  err: Error code.
  * @retval None
  */
void LCD_DisplayError(uint32_t err)
{
  I2S_CODEC_LCDConfig();

  /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

  LCD_SetTextColor(Red); 

  /* Clear the LCD */
  LCD_Clear(White);


  /* The memory initialazation failed */
  if (err == 1)
  {
    LCD_DisplayStringLine(Line7, memerr); 
  }

  /* The audio file initialization failed (wrong audio format or wrong file) */
  if (err == 2)
  {
    LCD_DisplayStringLine(Line7, fileerr); 
  }

  /* I2C communication failure occured */
  if (err == 3)
  {
    LCD_DisplayStringLine(Line7, i2cerr); 
  }

  LCD_DisplayStringLine(Line8, "Push JoyStick to    ");
  LCD_DisplayStringLine(Line9, "exit.               ");

  /* Disable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);

  while(ReadKey() == NOKEY)
  {
  }
}

/**
  * @brief  Initialize the LCD device and display the welcome screen.
  * @param  None
  * @retval None
  */
void I2S_CODEC_LCDConfig(void)
{
  /* Set the text and the background color */
  LCD_SetBackColor(Blue);
  LCD_SetTextColor(Black);
  LCD_Clear(White);

  /* Display the Titles */  
  LCD_DisplayStringLine(Line0, DemoTitle);
  LCD_DisplayStringLine(Line2, CmdTitle0); 
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
