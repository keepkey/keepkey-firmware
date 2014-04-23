/**
  ******************************************************************************
  * @file    i2s_codec.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   This file includes the I2S Codec driver for AK4343 Audio Codec.
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
#include "i2s_codec.h"

/* Private typedef -----------------------------------------------------------*/
typedef enum
{
  LittleEndian,
  BigEndian
}Endianness;

/* Private define ------------------------------------------------------------*/

/* Audio file header size */
#define HEADER_SIZE          100

/* EvalBoard pins related to the Codec */
#define Codec_PDN_GPIO	     GPIOG
#define Codec_PDN_Pin	     GPIO_Pin_11

/* Uncomment this line to enable verifying data sent to codec after each write opeation */
//#define VERIFY_WRITTENDATA

/* The 7 bits Codec adress mask */
#define CODEC_ADDRESS         0x27  /* b00100111 */ 

/* Audio Parsing Constants */
#define  ChunkID             0x52494646  /* correspond to the letters 'RIFF' */
#define  FileFormat          0x57415645  /* correspond to the letters 'WAVE' */
#define  FormatID            0x666D7420  /* correspond to the letters 'fmt ' */
#define  DataID              0x64617461  /* correspond to the letters 'data' */
#define  FactID              0x66616374  /* correspond to the letters 'fact' */

#define  WAVE_FORMAT_PCM     0x01
#define  FormatChunkSize     0x10
#define  Channel_MONO        0x01
#define  Channel_STEREO      0x02

#define  SampleRate_8000     8000
#define  SampleRate_16000    16000
#define  SampleRate_22050    22050
#define  SampleRate_44100    44100
#define  SampleRate_48000    48000
#define  Bits_Per_Sample_8   8
#define  Bits_Per_Sample_16  16

#define DUMMY_DATA           0x1111
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Audio Frequency value */
uint16_t i2saudiofreq = I2S_AudioFreq_8k;

/* Header Table containing the audio file information */
uint8_t HeaderTabIndex = 0;
uint8_t AudioFileHeader[HEADER_SIZE]; 

/* Audio Codec variables */
__IO uint32_t AudioFileAddress = AUDIO_FILE_ADDRESS; 
uint32_t AudioDataLength = 0;
uint32_t DataStartAddr = 0x0;
__IO uint32_t AudioDataIndex = 0;
static __IO uint32_t AudioReplay = 0xFFFF;
static uint32_t AudioReplayCount = 0xFFFF;
static __IO uint32_t SendDummyData = 0;
static __IO uint32_t AudioPlayStatus = AudioPlayStatus_STOPPED;
static uint32_t CurrentOutputDevice = OutputDevice_HEADPHONE;
static uint8_t CurrentVolume = DEFAULT_VOL;
static uint32_t errorcode = 0xFF;
static __IO uint32_t monovar = 0, tmpvar = 0;

/* Wave details names table */
WAVE_FormatTypeDef  WAVE_Format;
__IO ErrorCode  WaveFileStatus = Unvalid_RIFF_ID;   
 
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/
static void NVIC_Config(void); 
static void I2S_GPIO_Config(void);
static void I2C_Config(void);
static void I2S_Config(uint16_t Standard, uint16_t MCLKOutput, uint16_t AudioFreq);
static uint32_t CODEC_Config(uint16_t AudioOutput, uint16_t I2S_Standard, uint16_t I2S_MCLKOutput, uint8_t Volume);
static uint32_t CODEC_WriteRegister(uint32_t RegisterAddr, uint32_t RegisterValue);
static uint32_t CODEC_ReadRegister(uint32_t RegisterAddr);
static uint32_t ReadUnit(uint8_t NbrOfBytes, Endianness BytesFormat);
uint32_t AudioFile_Init(void);

/**
  * @brief  Initializes the I2S audio codec according parameters configured 
  *         by I2S_CODEC_Config function.
  * @param  OutputDevice: Could be OutoutDevice_SPEAKER or OutoutDevice_HEADPHONE.
  * @param  Address: Specifies the location of the audio file in the memory.
  * @retval 0: if all initializations are OK.
  *         1: if memory initialization failed (LD2 is turned on).
  *         2: if audio file initialization failed (LD2 is turned on).
  *         3: if Codec initialization failed (LD1 is turned on).
  */
uint32_t I2S_CODEC_Init(uint32_t OutputDevice, uint32_t Address)
{
	uint32_t count = 0;

  /* Set the audio file address */
  AudioFileAddress = (uint32_t) Address;

  /* Configure I2S interrupt Channel */
  NVIC_Config();

  /* Configure the I2S2, I2C1 and GPIOF pins */
  I2S_GPIO_Config(); 

	/* Read the Audio file to extract the audio data length and frequency */
  errorcode = AudioFile_Init();

  if (errorcode < 3)
  {
    /* Turn on LD2 connected to PF.07 */
    GPIO_SetBits(GPIOF, GPIO_Pin_7);
  
    return errorcode;
  }

  /* Configure the SPI2 peripheral in I2S mode */
  I2S_Config(I2S_STANDARD, I2S_MCLKOUTPUT, i2saudiofreq); 

  /* Set the current output device */
  CurrentOutputDevice = OutputDevice;

  /* Codec Configuration via I2C interface */
  count = CODEC_Config(OutputDevice, I2S_STANDARD, I2S_MCLKOUTPUT, DEFAULT_VOL);

  if (count != 0)
  {
    /* Turn on LD1 connected to PF.06 */
    GPIO_SetBits(GPIOF, GPIO_Pin_6);

    return 3;
  }

  /* Turn on LD4 connected to PF.09 */
  GPIO_SetBits(GPIOF, GPIO_Pin_9);

  return 0; /* Configuration is OK */
}

/**
  * @brief  Set AudioReplay variable value.
  * @param  Repetions: Number of repetitions
  * @retval None
  */
void I2S_CODEC_ReplayConfig(uint32_t Repetions)
{ 
  /* Audio Replay number set by user */
  AudioReplay = Repetions;
  
  /* Audio Replays number remaining (if AudioReplay != 0) */
  AudioReplayCount = Repetions;
}

/**
  * @brief  Plays the audio file.
  * @param  AudioStartPosition: Adress from which the wave data begin
  * @retval AudioDataIndex value.
  */
uint32_t I2S_CODEC_Play(uint32_t AudioStartPosition)
{   
	/* Send the read command to the media */
  Media_StartReadSequence(AudioFileAddress + AudioStartPosition + 1); 

  /* Set Playing status to inform other modules about the codec status */
  SetVar_AudioPlayStatus(AudioPlayStatus_PLAYING);

  /* Enable the I2S2 TXE Interrupt  => Generate the clocks*/ 
  SPI_I2S_ITConfig(SPI2, SPI_I2S_IT_TXE, ENABLE);

  return AudioDataIndex;
}

/**
  * @brief  Pause playing the audio file.
  * @param  None
  * @retval Current Position.
  */
uint32_t I2S_CODEC_Pause()
{
  /* Disable the I2S2 TXE Interrupt  => stop the clocks*/ 
  SPI_I2S_ITConfig(SPI2, SPI_I2S_IT_TXE, DISABLE);

  /* Set Paused status to inform other modules about the codec status */
  SetVar_AudioPlayStatus(AudioPlayStatus_PAUSED);
  
  /* Reset local variables */
  monovar = 0;
  tmpvar = 0;

  if (WAVE_Format.NumChannels == Channel_MONO) 
  {
    /* Force the parity of the address */ 
    AudioDataIndex &= 0xFFFFFFFE; 
  }
  /* Return the current data pointer position */
  return AudioDataIndex;
}

/**
  * @brief  Stop playing the audio file, reset the pointer and power off the Codec.
  * @param  None
  * @retval 0 if operation complete.
  */
uint32_t I2S_CODEC_Stop()
{
	/* Disable the I2S2 TXE Interrupt  => stop the clocks */ 
  SPI_I2S_ITConfig(SPI2, SPI_I2S_IT_TXE, DISABLE);

	/* Reinitialize the audio data pointer */
  AudioDataIndex = 0;

  /* Power off the Codec to save power and protect the Codec itself */
  I2S_CODEC_PowerDown(CodecPowerDown_SW);

  /* Set Paused status to inform other modules about the codec status */
  SetVar_AudioPlayStatus(AudioPlayStatus_STOPPED);

  /* Reset local variables */
  monovar = 0;
  tmpvar = 0;

  return 0;
}

/**
  * @brief  Controls the audio volume.
  * @param  direction: VolumeDirection_HIGH (0xF) to increase the volume, 
  *                    - VolumeDirection_LOW (0xA) to decrease  the volume
  *                    - VolumeDirection_LEVEL (0x0) to set a defined level of volume.
  * @param  Volume: the step of volume increqing/decreasing (when direction == 0)
  *                 or the volume level to be set (when direction != 0).
  * @retval 0-> correct communication, else wrong communication
  */
uint32_t I2S_CODEC_ControlVolume(uint32_t direction, uint8_t Volume)
{
	uint32_t counter = 0;

	if (direction == VolumeDirection_HIGH)
  {    
    /* Check if the volume high limit is reached */
		if (CurrentVolume < VOLStep)
    {
      CurrentVolume = 0;
    }
    else
    {
	    /* Save the current volume level */
      CurrentVolume = CODEC_ReadRegister(0x0A) - Volume;
    }
    
    /* Set the new volume */
    counter += CODEC_WriteRegister(0x0A, CurrentVolume);	  
  }
	else if (direction == VolumeDirection_LOW)
  {    
    /* Check if the volume low limit is reached */
		if (CurrentVolume > (0xFF - VOLStep))
    {
      CurrentVolume = 0xFF; 
    }
    else
    {
      /* Save the current volume level */
      CurrentVolume = CODEC_ReadRegister(0x0A) + Volume;
    }
   
    /* Set the new volume */
    counter += CODEC_WriteRegister(0x0A, CurrentVolume);	  
  }
  else if (direction == VolumeDirection_LEVEL) 
  {
    CurrentVolume = Volume;

    /* Set the new volume */
    counter += CODEC_WriteRegister(0x0A, Volume);	  
  }
  else
  {
    return 0xFF; /* Error verifying the Codec registers */
  }
  
  return counter;
}

/**
  * @brief  Enable or disable the MUTE mode by software
  * @param  Command: could be MUTEON to mute sound or MUTEOFF to restore volume
  * @retval None
  */
void I2S_CODEC_Mute(uint32_t Command)
{ 
	uint32_t tmp = 0;

	/* Read the current value of the config register number 0x0E */
  tmp = CODEC_ReadRegister(0x0E);

  /* Set the Mute mode */
	if (Command == MUTE_ON)
  {
    tmp |= 0x20; 
  }
  else /* MUTE_OFF Disable the Mute */
  {
    tmp &= 0xD1; 
  }
  
  /* Write back the CODEC config register w/the new value */
  CODEC_WriteRegister(0x0E, tmp);
}

/**
  * @brief  Forward function.
  * @param  Step: number of steps forward
  * @retval None
  */
void I2S_CODEC_ForwardPlay(uint32_t Step)
{   
  /* Pause Playing the audio file */
  I2S_CODEC_Pause();

  /* Increment the Audio pointer */
  IncrementVar_AudioDataIndex((AudioDataLength / 100) * Step);

  /* Insure the index parity */
  AudioDataIndex &= 0xFFFFFFFE;

  /* Resume playing from the new position */
  I2S_CODEC_Play((GetVar_AudioDataIndex()));
}

/**
  * @brief  Rewind function.
  * @param  Step: number of steps back
  * @retval None
  */
void I2S_CODEC_RewindPlay(uint32_t Step)
{   
  /* Pause Playing the audio file */
  I2S_CODEC_Pause();

  /* Increment the Audio pointer */
  DecrementVar_AudioDataIndex((AudioDataLength / 100) * Step);

  /* Insure the index parity */
  AudioDataIndex &= 0xFFFFFFFE;

  /* Resume playing from the new position */
  I2S_CODEC_Play((GetVar_AudioDataIndex()));
}

/**
  * @brief  Power down the Audio Codec.
  * @param  CodecPowerDown_Mode: could be CodecPowerDown_SW for power down after 
  *                              communication, CodecPowerDown_HW simply shutdown
  *                              the codec
  * @retval None
  */
void I2S_CODEC_PowerDown(uint32_t CodecPowerDown_Mode)
{
	if (CodecPowerDown_Mode == CodecPowerDown_SW)
  {
    /* Power down the DAC and the speaker (PMDAC and PMSPK bits)*/
    (void)CODEC_WriteRegister(0x00, 0x40);
    /* Power down the VCOM*/
    (void)CODEC_WriteRegister(0x00, 0x00); 
  }
  else /* CodecPowerDown_HW */
  {
		/* Power Down the Codec */
		GPIO_ResetBits(Codec_PDN_GPIO, Codec_PDN_Pin); 
  }	
}

/**
  * @brief  Reset the Audio Codec.
  * @param  None
  * @retval None
  */
void I2S_CODEC_Reset(void)
{
  /* Power Down the Codec */
	GPIO_ResetBits(Codec_PDN_GPIO, Codec_PDN_Pin); 

  /* wait for a delay to allow registers erasing */
  delay(0xFF);

  /* Power On the Codec after the power off => all registers are reinitialized*/
  GPIO_SetBits(Codec_PDN_GPIO, Codec_PDN_Pin);   
	 	
}

/**
  * @brief  Configure the Audio Codec output to Speaker or Headphone while the audio
  *         wave is Paused or stopped
  * @param  OutputDevice: could be OutputDevice_Speaker or OutputDevice_Headphone
  *                       or OutputDevice_Both 
  * @param  Address: Specifies the audio file location in the memory.
  * @retval 0: Operation done without failures.
  *         1: Memory failure occured.
  *         2: Audio file inialization failure occured
  *         3: I2C communication failure occured
  */
uint32_t I2S_CODEC_SpeakerHeadphoneSwap(uint32_t OutputDevice, uint32_t Address)
{ 
  uint32_t tmp_pointer = 0, err = 0;

  /* Reset all Codec Registers */
  I2S_CODEC_Reset();
 
  /* Save the current position */
  tmp_pointer = GetVar_AudioDataIndex();

  /* Reinitialize the CODEC with the new configured parameters */
  err = I2S_CODEC_Init(OutputDevice, Address);
  
  if (err != 0)
  {  
    return err;
  } 
 
  /* Restore the last pointer position */
  AudioDataIndex = tmp_pointer;
  
  /* Restore the last volume level */
  I2S_CODEC_ControlVolume(VolumeDirection_LEVEL, CurrentVolume);

  /* Play from current position */
  I2S_CODEC_Play(tmp_pointer);

  return 0;
}

/**
  * @brief  Check if STOP or PAUSE command are generated and performs the relative
  *         action (STOP or PAUSE playing)
  * @param  None
  * @retval None
  */
void I2S_CODEC_UpdateStatus(void)
{ 
  /* STOP command is generated => Stop playing the audio file */
  if ((GetVar_AudioPlayStatus() == AudioPlayStatus_STOPPED) && (SPI_I2S_GetFlagStatus(SPI2, I2S_FLAG_CHSIDE) == SET))
  {
    I2S_CODEC_Stop();
  }
  
  /* PAUSE Command is generated => PAUSE playing the audio File */
  if ((GetVar_AudioPlayStatus() == AudioPlayStatus_PAUSED) && (SPI_I2S_GetFlagStatus(SPI2, I2S_FLAG_CHSIDE) == SET))
  {
    I2S_CODEC_Pause();
  }
}

/**
  * @brief  returns DataStartAddr variable value (used by stm32f10x_it.c file).
  * @param  None
  * @retval AudioDataIndex
  */
uint32_t GetVar_DataStartAddr(void)
{ 
  return DataStartAddr;
}

/**
  * @brief  returns CurrentVolume variable value (used by extern files).
  * @param  None
  * @retval CurrentVolume
  */
uint8_t GetVar_CurrentVolume(void)
{ 
  return CurrentVolume;
}

/**
  * @brief  Checks the format of the .WAV file and gets information about the audio
  *         format. This is done by reading the value of a number of parameters 
  *         stored in the file header and comparing these to the values expected
  *         authenticates the format of a standard .WAV  file (44 bytes will be read).
  *         If it is a valid .WAV file format, it continues reading the header
  *         to determine the  audio format such as the sample rate and the sampled
  *         data size. If the audio format is supported by this application,
  *         it retrieves the audio format in WAVE_Format structure and returns
  *         a zero value. Otherwise the function fails and the return value is nonzero.
  *         In this case, the return value specifies the cause of  the function fails.
  *         The error codes that can be returned by this function are declared 
  *         in the header file.
  * @param  None
  * @retval Zero value if the function succeed, otherwise it return a nonzero value
  *         which specifies the error code.
  */
ErrorCode I2S_CODEC_WaveParsing(uint8_t* HeaderTab)
{
  uint32_t Temp = 0x00;
  uint32_t ExtraFormatBytes = 0; 
  
  /* Initialize the HeaderTabIndex variable */
  HeaderTabIndex = 0;

  /* Read chunkID, must be 'RIFF'	----------------------------------------------*/
  Temp = ReadUnit(4, BigEndian);
  if(Temp != ChunkID)
  {
    return(Unvalid_RIFF_ID);
  }
  /* Read the file length ----------------------------------------------------*/
  WAVE_Format.RIFFchunksize = ReadUnit(4, LittleEndian);
	
  /* Read the file format, must be 'WAVE' ------------------------------------*/
  Temp = ReadUnit(4, BigEndian);
  if(Temp != FileFormat)
  {
    return(Unvalid_WAVE_Format);
  }
  /* Read the format chunk, must be 'fmt ' -----------------------------------*/
  Temp = ReadUnit(4, BigEndian);
  if(Temp != FormatID)
  {
    return(Unvalid_FormatChunk_ID);
  }
  /* Read the length of the 'fmt' data, must be 0x10 -------------------------*/
  Temp = ReadUnit(4, LittleEndian);
  if(Temp != 0x10)
  {
    ExtraFormatBytes = 1;
  }
  /* Read the audio format, must be 0x01 (PCM) -------------------------------*/
  WAVE_Format.FormatTag = ReadUnit(2, LittleEndian);
  if(WAVE_Format.FormatTag != WAVE_FORMAT_PCM)
  {
    return(Unsupporetd_FormatTag);	
  }	
  /* Read the number of channels: 0x02->Stereo 0x01->Mono --------------------*/
  WAVE_Format.NumChannels = ReadUnit(2, LittleEndian);

  /* Read the Sample Rate ----------------------------------------------------*/
  WAVE_Format.SampleRate = ReadUnit(4, LittleEndian);

  /* Update the I2S_AudioFreq value according to the .WAV file Sample Rate */
  switch(WAVE_Format.SampleRate)
  {
    case SampleRate_8000 : i2saudiofreq = I2S_AudioFreq_8k;  break; 
    case SampleRate_16000: i2saudiofreq = I2S_AudioFreq_16k; break; 
    case SampleRate_22050: i2saudiofreq = I2S_AudioFreq_22k; break; 	
    case SampleRate_44100: i2saudiofreq = I2S_AudioFreq_44k; break;  		
    case SampleRate_48000: i2saudiofreq = I2S_AudioFreq_48k; break;  		
    default: return(Unsupporetd_Sample_Rate);
  }	
  /* Read the Byte Rate ------------------------------------------------------*/
  WAVE_Format.ByteRate = ReadUnit(4, LittleEndian);
	
  /* Read the block alignment ------------------------------------------------*/
  WAVE_Format.BlockAlign = ReadUnit(2, LittleEndian);
	
  /* Read the number of bits per sample --------------------------------------*/
  WAVE_Format.BitsPerSample = ReadUnit(2, LittleEndian);
  if(WAVE_Format.BitsPerSample != Bits_Per_Sample_16)
  {
    return(Unsupporetd_Bits_Per_Sample);
  }
  /* If there are Extra format bytes, these bytes will be defined in "Fact Chunk" */
  if(ExtraFormatBytes == 1)
  {
    /* Read th Extra format bytes, must be 0x00 ------------------------------*/
    Temp = ReadUnit(2, LittleEndian);
    if(Temp != 0x00)
    {
      return(Unsupporetd_ExtraFormatBytes);
    }
    /* Read the Fact chunk, must be 'fact' -----------------------------------*/
    Temp = ReadUnit(4, BigEndian);
    if(Temp != FactID)
    {
      return(Unvalid_FactChunk_ID);
    }
    /* Read Fact chunk data Size ---------------------------------------------*/
    Temp = ReadUnit(4, LittleEndian);

    /* Set the index to start reading just after the header end */
    HeaderTabIndex += Temp;
  }
  /* Read the Data chunk, must be 'data' -------------------------------------*/
  Temp = ReadUnit(4, BigEndian);
  if(Temp != DataID)
  {
    return(Unvalid_DataChunk_ID);
  }
  /* Read the number of sample data ------------------------------------------*/
  WAVE_Format.DataSize = ReadUnit(4, LittleEndian);

  /* Set the data pointer at the beginning of the effective audio data */
	DataStartAddr += HeaderTabIndex;
  
  return(Valid_WAVE_File);	
}

/**
  * @brief  returns AudioDataIndex variable value (used by stm32f10x_it.c file).
  * @param  None
  * @retval AudioDataIndex
  */
uint32_t GetVar_AudioDataIndex(void)
{ 
  return AudioDataIndex;
}

/**
  * @brief  Sets AudioDataIndex variable value (used by stm32f10x_it.c file).
  * @param  None
  * @retval AudioDataIndex
  */
void SetVar_AudioDataIndex(uint32_t value)
{ 
  AudioDataIndex = value;
}

/**
  * @brief  Increment the AudioDataIndex variable.
  * @param  IncrementNumber: number of incrementations.
  * @retval None
  */
void IncrementVar_AudioDataIndex(uint32_t IncrementNumber)
{ 
  AudioDataIndex += (uint32_t)IncrementNumber;
  
  if (AudioDataIndex >= AudioDataLength)
  {
    ResetVar_AudioDataIndex();
    Decrement_AudioReplay();
  }
}

/**
  * @brief  Set the AudioDataIndex variable to 1.
  * @param  None
  * @retval None
  */
void DecrementVar_AudioDataIndex(uint32_t DecrementNumber)
{ 
  if (DecrementNumber >= AudioDataIndex)
  {
    ResetVar_AudioDataIndex();
  }
  else
  { 
    AudioDataIndex -= (uint32_t)DecrementNumber;
  }
}

/**
  * @brief  Reset the AudioDataIndex variable.
  * @param  None
  * @retval None
  */
void ResetVar_AudioDataIndex(void)
{ 
  AudioDataIndex = DataStartAddr;

  /* Send the read command to the media */
  Media_StartReadSequence(AudioFileAddress + DataStartAddr + 1);
}

/**
  * @brief  returns SendDummyData variable value (used by stm32f10x_it.c file).
  * @param  None
  * @retval SendDummyData
  */
uint32_t GetVar_SendDummyData(void)
{ 
  return SendDummyData;
}

/**
  * @brief  Set the SendDummyData variable to 1.
  * @param  None
  * @retval SendDummyData
  */
uint32_t SetVar_SendDummyData(void)
{ 
  SendDummyData = (uint32_t)0x1;
 
  return SendDummyData;
}

/**
  * @brief  Reset the SendDummyData variable to 0.
  * @param  None
  * @retval SendDummyData
  */
uint32_t ResetVar_SendDummyData(void)
{ 
  SendDummyData = (uint32_t)0;
 
  return SendDummyData;
}

/**
  * @brief  returns AudioPlayStatus variable value (used by stm32f10x_it.c file).
  * @param  None
  * @retval AudioPlayStatus value.
  */
uint32_t GetVar_AudioPlayStatus(void)
{ 
  return AudioPlayStatus;
}

/**
  * @brief  Set the AudioDataIndex variable to Status.
  * @param  Status: could be AudioPlayStatus_STOPPED, AudioPlayStatus_PLAYING
  *                 or AudioPlayStatus_PAUSED.
  * @retval AudioPlayStatus value.
  */
uint32_t SetVar_AudioPlayStatus(uint32_t Status)
{ 
  AudioPlayStatus = (uint32_t)Status;
 
  return AudioPlayStatus;
}

/**
  * @brief  returns AudioReplay variable value.
  * @param  None
  * @retval AudioReplay value.
  */
uint32_t GetVar_AudioReplay(void)
{ 
  return AudioReplay;
}

/**
  * @brief  Decrement the AudioReplayCount variable if AudioReplay is different
  *         from zero (infinite replaying).
  * @param  None
  * @retval AudioPlayStatus value.
  */
void Decrement_AudioReplay(void)
{ 
  if (AudioReplay != 0)
  {
    AudioReplayCount--;

		if (AudioReplayCount == 0)
	  {
	    /* Command the Stop of the audio playing */ 
	    SetVar_AudioPlayStatus(AudioPlayStatus_STOPPED);
	    
	    /* Reset the counter */
	    AudioReplayCount = AudioReplay;
	  }
  }
}

/**
  * @brief  Get the current output device selected.
  * @param  None
  * @retval None
  */
uint32_t GetVar_CurrentOutputDevice(void)
{ 
  return CurrentOutputDevice;
}

/**
  * @brief  Get the current audio file data length.
  * @param  None
  * @retval None
  */
uint32_t GetVar_AudioDataLength(void)
{ 
  return AudioDataLength;
}

/**
  * @brief  Get the current audio frequency.
  * @param  None
  * @retval None
  */
uint16_t GetVar_i2saudiofreq(void)
{ 
  return i2saudiofreq;
}

/**
  * @brief  Initializes the SPI_Flsh and returns the Wavadatalength variable.
  * @param  None
  * @retval The length of the wave file read from the SPI_Flash
  *           1 if an error occured when initializing the memory.
  *           2 if an error occured on the audio file intialization.
  */
uint32_t AudioFile_Init(void)
{
  uint32_t err = 0;

  /* Initialize the media support */
  err = Media_Init();

  /* Check if Memory initialization is OK */
  if (err != 0)
  {
    return 1;
  }

  /* Read a Byte buffer and store it in the Header table*/
  Media_BufferRead(AudioFileHeader, AudioFileAddress, HEADER_SIZE);

  /* Read and check the audio file Header */
	WaveFileStatus = I2S_CODEC_WaveParsing(AudioFileHeader);

	/* Check if the selected file is a correct wave file */
  if(WaveFileStatus == Valid_WAVE_File)
  {
	 	/* Read and set the audio data length (/!\ data are counted as BYTES /!\) */ 
	  AudioDataLength = WAVE_Format.DataSize ;  
	  
	  /* Read and set the audio frequency */
	  i2saudiofreq = (uint16_t)WAVE_Format.SampleRate;

    /* Return the audio file length */
		return AudioDataLength;
  }
	else /* Wrong wave file */
  {
   	return 2;
  }
}

/**
  * @brief  Configure the I2Ss NVIC channel.
  * @param  None
  * @retval None
  */
static void NVIC_Config(void)
{
  NVIC_InitTypeDef NVIC_InitStructure;

	/* SPI2 IRQ Channel configuration */
  NVIC_InitStructure.NVIC_IRQChannel = SPI2_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);
}

/**
  * @brief  Initializes the GPIO pins used by the codec application.
  * @param  None
  * @retval None
  */
static void I2S_GPIO_Config(void)
{
  GPIO_InitTypeDef GPIO_InitStructure;

  /* Enable GPIOB, GPIOC and AFIO clock */
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOB | RCC_APB2Periph_GPIOC | RCC_APB2Periph_GPIOG | 
                         RCC_APB2Periph_GPIOF | RCC_APB2Periph_AFIO, ENABLE);

  /* I2S2 SD, CK and WS pins configuration */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_12 | GPIO_Pin_13 | GPIO_Pin_15;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_PP;
  GPIO_Init(GPIOB, &GPIO_InitStructure);

  /* I2S2 MCK pin configuration */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_6 | GPIO_Pin_7;
  GPIO_Init(GPIOC, &GPIO_InitStructure);
  
  /* I2C1 SCL PB6 and SDA PB7 pins configuration */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_6 | GPIO_Pin_7;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_OD;
  GPIO_Init(GPIOB, &GPIO_InitStructure);
  
  /* Enable the I2C1 APB1 clock */
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_I2C1, ENABLE);
  
  /* Turn Off All LEDs */
  STM_EVAL_LEDOff(LED1);
  STM_EVAL_LEDOff(LED2);
  STM_EVAL_LEDOff(LED3);
  STM_EVAL_LEDOff(LED4);
  
  GPIO_ResetBits(Codec_PDN_GPIO, Codec_PDN_Pin);
  
  /* Configure the Codec PDN pin as output PushPull */
  GPIO_InitStructure.GPIO_Pin = Codec_PDN_Pin;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
  GPIO_Init(Codec_PDN_GPIO, &GPIO_InitStructure);
}

/**
  * @brief  Configure the I2S Peripheral.
  * @param  Standard: I2S_Standard_Phillips, I2S_Standard_MSB or I2S_Standard_LSB
  * @param  MCLKOutput: I2S_MCLKOutput_Enable or I2S_MCLKOutput_Disable
  * @param  AudioFreq: I2S_AudioFreq_8K, I2S_AudioFreq_16K, I2S_AudioFreq_22K,
  *                    I2S_AudioFreq_44K or I2S_AudioFreq_48K  
  * @retval None
  */
static void I2S_Config(uint16_t Standard, uint16_t MCLKOutput, uint16_t AudioFreq)
{
	I2S_InitTypeDef I2S_InitStructure; 

	/* Enable I2S2 APB1 clock */
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_SPI2, ENABLE);

  /* Deinitialize SPI2 peripheral */
  SPI_I2S_DeInit(SPI2); 

	/* I2S2 peripheral configuration */
  I2S_InitStructure.I2S_Mode = I2S_Mode_MasterTx;
  I2S_InitStructure.I2S_Standard = Standard;
  I2S_InitStructure.I2S_DataFormat = I2S_DataFormat_16b;
  I2S_InitStructure.I2S_MCLKOutput = MCLKOutput;
  I2S_InitStructure.I2S_AudioFreq = AudioFreq;
  I2S_InitStructure.I2S_CPOL = I2S_CPOL_Low;  
  I2S_Init(SPI2, &I2S_InitStructure);

  /* Disable the I2S2 TXE Interrupt */ 
  SPI_I2S_ITConfig(SPI2, SPI_I2S_IT_TXE, DISABLE);
 
  /* Enable the SPI2/I2S2 peripheral */
  I2S_Cmd(SPI2, ENABLE);
}

/**
  * @brief  Configure the I2C1 Peripheral.
  * @param  None
  * @retval None
  */
static void I2C_Config(void)
{
	I2C_InitTypeDef I2C_InitStructure;

  /* I2C1 configuration */
  I2C_InitStructure.I2C_Mode = I2C_Mode_I2C;
  I2C_InitStructure.I2C_DutyCycle = I2C_DutyCycle_2;
  I2C_InitStructure.I2C_OwnAddress1 = 0x33;
  I2C_InitStructure.I2C_Ack = I2C_Ack_Enable;
  I2C_InitStructure.I2C_AcknowledgedAddress = I2C_AcknowledgedAddress_7bit;
  I2C_InitStructure.I2C_ClockSpeed = 200000;
  I2C_Init(I2C1, &I2C_InitStructure);
}

/**
  * @brief  Configure the Codec in Headphone mode.
  * @param  OutputDevice: OutputDeviceHEADPHONE or OutputDeviceSPEAKER
  * @param  I2S_Standard: I2S communication standard could be I2S_Standard_Phillips
  *         I2S_Standard_MSB or I2S_Standard_LSB.
  * @param  I2S_MCLKOutput: could be I2S_MCLKOutput_
  * @param  Volume:
  * @retval 0-> correct communication, else wrong communication
  */
uint32_t CODEC_Config(uint16_t OutputDevice, uint16_t I2S_Standard, uint16_t I2S_MCLKOutput, uint8_t Volume)
{
  uint32_t Standard =0, counter = 0, PLLMode = 0;

	/* Command the sending of dummy data */
  ResetVar_SendDummyData();

	/* Reset the Codec Registers */
	I2S_CODEC_Reset(); 

  /* Determine the I2S standard used */
  switch (I2S_Standard)
  {
    case I2S_Standard_Phillips: Standard = 0x03; break;
    case I2S_Standard_MSB:      Standard = 0x02; break;
    default :                   Standard = 0x01; break;
  }
  
  /* HEADPHONE codec configuration */
  if ((OutputDevice & OutputDevice_HEADPHONE) != 0)
  {
		/* PLL Slave SD/WS reference mode ----------------------*/
		if (I2S_MCLKOutput == I2S_MCLKOutput_Disable)
		{
		  /* set the PLLMode variable */
			PLLMode = 0x1;
		
		  /* Phillips(0x03)/MSB(0x02)/LSB(0x01) mode with PLL */
		  counter += CODEC_WriteRegister(0x04, (Standard | 0x20));
		  /* MCKI input frequency = 256.Fs */
		  counter += CODEC_WriteRegister(0x05, 0x03);
		  /* VCOM Power up (PMVCM bit)*/
		  counter += CODEC_WriteRegister(0x00, 0x40);
		  /* Enable PLL*/
		  counter += CODEC_WriteRegister(0x01, 0x01);
		}
		/* Ext Slave mode with no PLL --------------------------*/
		else
		{
		  /* Reset the PLL mode variable */
			PLLMode = 0;
		
		  /* Phillips(0x03)/MSB(0x02)/LSB(0x01) mode with no PLL */
		  counter += CODEC_WriteRegister(0x04, Standard);
		  /* MCKI input frequency = 256.Fs */
		  counter += CODEC_WriteRegister(0x05, 0x00);
		  /* VCOM Power up (PMVCM bit)*/
		  counter += CODEC_WriteRegister(0x00, 0x40);
		}
		
		/* Command the sending of dummy data */
		SetVar_SendDummyData();
		
		/* Enable the I2S2 TXE Interrupt  => Generate the clocks*/ 
		SPI_I2S_ITConfig(SPI2, SPI_I2S_IT_TXE, ENABLE);
		
		/* Extra Configuration (of the ALC) */
		counter += CODEC_WriteRegister(0x06, 0x3C );
		counter += CODEC_WriteRegister(0x08, 0xE1 );
		counter += CODEC_WriteRegister(0x0B, 0x00 );
		counter += CODEC_WriteRegister(0x07, 0x20 );
		counter += CODEC_WriteRegister(0x09, 0xC1 );
		counter += CODEC_WriteRegister(0x0C, 0xC1 );
		
    /* Uncomment these lines and set the correct filters values to use the 
        codec digital filters (for more details refer to the codec datasheet) */
		//  /* Filter 1 programming as High Pass filter (Fc=500Hz, Fs=8KHz, K=20, A=1, B=1) */
		//  counter += CODEC_WriteRegister(0x1C, 0x01);
		//  counter += CODEC_WriteRegister(0x1D, 0x80);
		//  counter += CODEC_WriteRegister(0x1E, 0xA0);
		//  counter += CODEC_WriteRegister(0x1F, 0x0B);
		
		//  /* Filter 3 programming as Low Pass filter (Fc=20KHz, Fs=8KHz, K=40, A=1, B=1) */
		//  counter += CODEC_WriteRegister(0x1C, 0x01);
		//  counter += CODEC_WriteRegister(0x1D, 0x00);
		//  counter += CODEC_WriteRegister(0x1E, 0x01);
		//  counter += CODEC_WriteRegister(0x1F, 0x01);
		
		//  /* Equilizer programming BP filter (Fc1=20Hz, Fc2=2.5KHz, Fs=44.1KHz, K=40, A=?, B=?, C=?) */
		//  counter += CODEC_WriteRegister(0x16, 0x00);
		//  counter += CODEC_WriteRegister(0x17, 0x75);
		//  counter += CODEC_WriteRegister(0x18, 0x00);
		//  counter += CODEC_WriteRegister(0x19, 0x01);
		//  counter += CODEC_WriteRegister(0x1A, 0x00);
		//  counter += CODEC_WriteRegister(0x1B, 0x51);
		
		/* MCKI is 256.Fs with no PLL */
		counter += CODEC_WriteRegister(0x05, 0x00 );
		/* Switch control from DAC to Headphone */
		counter += CODEC_WriteRegister(0x0F, 0x09 );
		/* Bass Boost and Demphasis enable */
		counter += CODEC_WriteRegister(0x0E, 0x18 );
		/* Left Channel Digital Volume control */
		counter += CODEC_WriteRegister(0x0A, Volume);  
		/* Right Channel Digital Volume control */
		counter += CODEC_WriteRegister(0x0D, Volume);
		/* Power up MIN and DAC (PMMIN and PMDAC bits)*/
		counter += CODEC_WriteRegister(0x00, 0x74);
		/* Enable Slave mode and Left/Right HP lines*/
		counter += CODEC_WriteRegister(0x01, (0x30 | PLLMode));
		/* Exit HP mute mode */
		counter += CODEC_WriteRegister(0x01, (0x70 | PLLMode));   
  }

  /* SPEAKER codec configuration */
  if ((OutputDevice & OutputDevice_SPEAKER) != 0)
  {
		/* PLL Slave SD/WS reference mode ----------------------*/
		if (I2S_MCLKOutput == I2S_MCLKOutput_Disable)
		{
		  /* Phillips(0x03)/MSB(0x02)/LSB(0x01) mode with no PLL */
		  counter += CODEC_WriteRegister(0x04, (Standard | 0x20));
		  /* MCKI input frequency = 256.Fs */
		  counter += CODEC_WriteRegister(0x05, 0x03);
		  /* VCOM Power up (PMVCM bit)*/
		  counter += CODEC_WriteRegister(0x00, 0x40);
		  /* Enable PLL*/
		  counter += CODEC_WriteRegister(0x01, 0x01);
		}
		/* Ext Slave mode with no PLL --------------------------*/
		else
		{
		  /* Phillips(0x03)/MSB(0x02)/LSB(0x01) mode with no PLL */
		  counter += CODEC_WriteRegister(0x04, Standard);
		  /* MCKI input frequency = 256.Fs */
		  counter += CODEC_WriteRegister(0x05, 0x00);
		  /* VCOM Power up (PMVCM bit)*/
		  counter += CODEC_WriteRegister(0x00, 0x40);
		}
	
	  /* Command the sending of dummy data */
	  SetVar_SendDummyData();
	
	  /* Enable the I2S2 TXE Interrupt  => Generate the clocks*/ 
	  SPI_I2S_ITConfig(SPI2, SPI_I2S_IT_TXE, ENABLE);
	  
	  /* ReSelect the MCKI frequency (FS0-1 bits): 256.Fs */
	  counter += CODEC_WriteRegister(0x05, 0x02 );
	  /* Set up the path "DAC->Speaker-Amp" with no power save (DACS and SPPSN bits) */ 
	  counter += CODEC_WriteRegister(0x02, 0x20 );
	  /* Speaker Gain (SPKG0-1 bits): Gain=+10.65dB(ALC off)/+12.65(ALC on) */
	  counter += CODEC_WriteRegister(0x03, 0x10);
	
	  /* Extra Configuration (of the ALC) */
	  counter += CODEC_WriteRegister(0x06, 0x3C );
	  counter += CODEC_WriteRegister(0x08, 0xE1 );
	  counter += CODEC_WriteRegister(0x0B, 0x00 );
	  counter += CODEC_WriteRegister(0x07, 0x20 );
	  counter += CODEC_WriteRegister(0x09, 0x91 );
	  counter += CODEC_WriteRegister(0x0C, 0x91 );
	
	  /* Left Channel Digital Volume control */
	  counter += CODEC_WriteRegister(0x0A, Volume);  
	  /* Right Channel Digital Volume control */
	  counter += CODEC_WriteRegister(0x0D, Volume);
	  /* Power up Speaker and DAC (PMSPK and PMDAC bits)*/
	  counter += CODEC_WriteRegister(0x00, 0x54);
	  /* Set up the path "DAC -> Speaker-Amp" with no power save */ 
	  counter += CODEC_WriteRegister(0x02, 0xA0 /*0xA1*/);   
  }

  /* Disable the I2S2 TXE Interrupt */ 
  SPI_I2S_ITConfig(SPI2, SPI_I2S_IT_TXE, DISABLE);
  
	/* Disable the sending of Dummy data */
	ResetVar_SendDummyData();

  /* Return the counter value */
	return counter;
}

/**
  * @brief  Writes a value in a register of the audio Codec through I2C.
  * @param  RegisterAddr: The target register adress (between 00x and 0x24)
  * @param  RegisterValue: The target register value to be written 
  *         Verify: 0-> Don't verify the written data, 1-> Verify the written data
  * @retval 0  -> Correct write operation
  *         !0 -> Incorrect write operation
  */
uint32_t CODEC_WriteRegister(uint32_t RegisterAddr, uint32_t RegisterValue)
{
	uint32_t read_verif = 0;
  
	/* Reset all I2C2 registers */       
  I2C_SoftwareResetCmd(I2C1, ENABLE);
  I2C_SoftwareResetCmd(I2C1, DISABLE);

  /* Enable the I2C1 peripheral  */
  I2C_Cmd(I2C1, ENABLE);

  /* Configure the I2C peripheral */
	I2C_Config();
	  
  /* Begin the config sequence */
  I2C_GenerateSTART(I2C1, ENABLE);
  
  /* Test on EV5 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT))
  {}  
  /* Transmit the slave address and enable writing operation */
  I2C_Send7bitAddress(I2C1, CODEC_ADDRESS, I2C_Direction_Transmitter);
  
  /* Test on EV6 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED))
  {}  
  /* Transmit the first address for r/w operations */
  I2C_SendData(I2C1, RegisterAddr);
  
  /* Test on EV8 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED))
  {} 
   
  /* Prepare the register value to be sent */
  I2C_SendData(I2C1, RegisterValue);

  /* Test on EV8 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED))
  {}
   
  /* End the configuration sequence */
  I2C_GenerateSTOP(I2C1, ENABLE);
  
  /* Verify (if needed) that the loaded data is correct  */
#ifdef VERIFY_WRITTENDATA
  /* Read the just written register*/
  read_verif = CODEC_ReadRegister(RegisterAddr);

  /* Load the register and verify its value  */
  if(read_verif != RegisterValue)
  {
    /* Control data wrongly tranfered */
		read_verif = 1;
  }
	else
	{
    /* Control data correctly transfered */
		read_verif = 0;
	}
#endif

  /* Return the verifying value: 0 (Passed) or 1 (Failed) */
  return read_verif;
}

/**
  * @brief  Reads a register of the audio Codec through I2C.
  * @param  RegisterAddr: The target register adress (between 00x and 0x24)
  * @retval The value of the read register
  */
uint32_t CODEC_ReadRegister(uint32_t RegisterAddr)
{
  uint32_t tmp = 0;

  /* Disable the I2C1 peripheral  */
  I2C_Cmd(I2C1, DISABLE);

	/* Reset all I2C2 registers */       
  I2C_SoftwareResetCmd(I2C1, ENABLE);
  I2C_SoftwareResetCmd(I2C1, DISABLE);
  
  /* Configure the I2C peripheral */
	I2C_Config();

  /* Enable the I2C peripheral */
  I2C_GenerateSTART(I2C1, ENABLE);
  
  /* Test on EV5 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT))
  {} 

	/* Disable Acknowledgement */
  I2C_AcknowledgeConfig(I2C1, DISABLE);
	 
  /* Transmit the slave address and enable writing operation */
  I2C_Send7bitAddress(I2C1, CODEC_ADDRESS, I2C_Direction_Transmitter);
  
  /* Test on EV6 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED))
  {}
    
  /* Transmit the first address for r/w operations */
  I2C_SendData(I2C1, RegisterAddr);
  
  /* Test on EV8 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED))
  {}

  /* Regenerate a start condition */
  I2C_GenerateSTART(I2C1, ENABLE);
  
  /* Test on EV5 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT))
  {} 
   
  /* Transmit the slave address and enable writing operation */
  I2C_Send7bitAddress(I2C1, CODEC_ADDRESS, I2C_Direction_Receiver);
  
  /* Test on EV6 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_RECEIVER_MODE_SELECTED))
  {}

  /* Test on EV7 and clear it */
  while(!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_RECEIVED))
  {} 

  /* End the configuration sequence */
  I2C_GenerateSTOP(I2C1, ENABLE);

	/* Load the register value */
	tmp = I2C_ReceiveData(I2C1);

 	/* Disable Acknowledgement */
  I2C_AcknowledgeConfig(I2C1, ENABLE);

  /* Return the read value */
	return tmp;  
}

/**
  * @brief  Reads a number of bytes from the SPI Flash and reorder them in Big or little endian.
  * @param  NbrOfBytes : number of bytes to read.
  *         This parameter must be a number between 1 and 4.
  * @param  Endians : specifies the bytes endianness.
  *                   This parameter can be one of the following values:
  *                   - LittleEndian
  *                   - BigEndian
  * @retval Bytes read from the SPI Flash.
  */
static uint32_t ReadUnit(uint8_t NbrOfBytes, Endianness BytesFormat)
{
  uint32_t index = 0;
  uint32_t Temp = 0;

  if(BytesFormat == LittleEndian)
  {
    for(index = 0; index < NbrOfBytes; index++)
    {
      Temp |= AudioFileHeader[HeaderTabIndex++] << (index * 8);
    }
  }
  else
  {
    for(index = NbrOfBytes; index != 0; index--)
    {
      Temp |= AudioFileHeader[HeaderTabIndex++] << ((index-1) * 8);
    }
  }

  return Temp;
}

/**
  * @brief  Read one half word from the media (SPI_Flash/NOR/NAND memories..)
  * @param  Offset: the adress offset for read operation
  * @retval Data read from the media memory.
  */
uint16_t Media_ReadHalfWord(uint32_t Offset)
{ 
  GPIO_InitTypeDef GPIO_InitStructure; 

  /* Test if the left channel is to be sent */
  if(monovar == 0)
  {
      /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
      RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

      /* Enable FSMC Bank1_NOR Bank */
      FSMC_NORSRAMCmd(FSMC_Bank1_NORSRAM2, ENABLE);

      /* NE2 configuration */
      GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_PP;
      GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
      GPIO_InitStructure.GPIO_Pin = GPIO_Pin_9;
      GPIO_Init(GPIOG, &GPIO_InitStructure);
      
      tmpvar =  (*(__IO uint16_t *) (AudioFileAddress + Offset));

      /* Disable FSMC Bank1_NOR Bank */
      FSMC_NORSRAMCmd(FSMC_Bank1_NORSRAM2, DISABLE);

      GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
      GPIO_Init(GPIOG, &GPIO_InitStructure);
      GPIO_SetBits(GPIOG, GPIO_Pin_9);
       
      /* Disable the FSMC that share a pin w/ I2C1 (LBAR) */
      RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);
      
      /* Increment the mono variable only if the file is in mono format */   
      if(WAVE_Format.NumChannels == Channel_MONO)
      {
        /* Increment the monovar variable */
        monovar++;
      }
   
      /* Return the read value */
      return tmpvar;
  }
  /* Right channel to be sent in mono format */
  else 
  {
    /* Reset the monovar variable */
    monovar = 0;
   
   /* Return the previous read data in mono format */
    return tmpvar;
  }	
}

/**
  * @brief  Read one byte from the media (SPI_Flash/NOR/NAND memories..)
  * @param  Offset: the adress offset for read operation
  * @retval Data read from the media memory.
  */
uint8_t Media_ReadByte(uint32_t Offset)
{ 
  uint8_t tmp = 0;
  GPIO_InitTypeDef GPIO_InitStructure; 
    
  /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

  /* Enable FSMC Bank1_NOR Bank */
  FSMC_NORSRAMCmd(FSMC_Bank1_NORSRAM2, ENABLE);

  /* NE2 configuration */
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_PP;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_9;
  GPIO_Init(GPIOG, &GPIO_InitStructure);

  /* Read data from the specified location */
  tmp =  (*(__IO uint8_t *) (AudioFileAddress + Offset));

  /* Disable FSMC Bank1_NOR Bank */
  FSMC_NORSRAMCmd(FSMC_Bank1_NORSRAM2, DISABLE);

  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
  GPIO_Init(GPIOG, &GPIO_InitStructure);
  GPIO_SetBits(GPIOG, GPIO_Pin_9);
       
  /* Disable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);

	return tmp;
}

/**
  * @brief  Read one byte from the media (SPI_Flash/NOR/NAND memories..)
  * @param  Offset: the adress offset for read operation
  * @retval 0 if initialization is OK
  *         1 if initialization failed..
  */
uint32_t Media_Init(void)
{ 
  GPIO_InitTypeDef GPIO_InitStructure; 

  /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

  /* Initialize the FSMC NOR Flash Interface */
  NOR_Init();

  /* Set the NOR read modes */  
  NOR_ReturnToReadMode();

  /* Disable FSMC Bank1_NOR Bank */
  FSMC_NORSRAMCmd(FSMC_Bank1_NORSRAM2, DISABLE);

  /* NE2 configuration */
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_PP;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_9;
  GPIO_Init(GPIOG, &GPIO_InitStructure);
  GPIO_SetBits(GPIOG, GPIO_Pin_9);
       
  /* Disable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);

  return 0;
}

/**
  * @brief  Read a buffer from the memory media 
  * @param  pBuffer: Destination buffer address
  * @param  ReadAddr: start reading position
  * @param  NumByteToRead: size of the buffer to read
  * @retval None
  */
void Media_BufferRead(uint8_t* pBuffer, uint32_t ReadAddr, uint16_t NumByteToRead)
{ 
  GPIO_InitTypeDef GPIO_InitStructure; 
    
  /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

  /* Enable FSMC Bank1_NOR Bank */
  FSMC_NORSRAMCmd(FSMC_Bank1_NORSRAM2, ENABLE);

  /* NE2 configuration */
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_PP;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_9;
  GPIO_Init(GPIOG, &GPIO_InitStructure);

  /* Read the data */
  while(NumByteToRead--)
  {
    *pBuffer++ = *(__IO uint8_t *)ReadAddr++;
  }

  /* Disable FSMC Bank1_NOR Bank */
  FSMC_NORSRAMCmd(FSMC_Bank1_NORSRAM2, DISABLE);

  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
  GPIO_Init(GPIOG, &GPIO_InitStructure);
  GPIO_SetBits(GPIOG, GPIO_Pin_9);
       
  /* Disable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);
}

/**
  * @brief  Initialize reading sequence on the media.
  * @param  ReadAddr: start reading position
  * @retval None
  */
void Media_StartReadSequence(uint32_t ReadAddr)
{
  /* This function could be used for memories needing a start read sequence
     like SPI_Flash memory */ 
}

/**
  * @brief  Sends the audio data using the SPI2 peripheral and checks the audio 
  *         playing status (if a command (Pause/Stop) is pending the playing status
  *         is updated). If the TXE flag interrupt is used to synchronize data sending,
  *         this function should be called in the SPI2 ISR.
  * @param  None
  * @retval None
  */
void I2S_CODEC_DataTransfer(void)
{
  /* Audio codec configuration section -------------------------------------*/
  if (GetVar_SendDummyData() == 1) 
  {
    /* Send a dummy data just to generate the I2S clock */
    SPI_I2S_SendData(SPI2, DUMMY_DATA);
  }
  /* Audio codec communication section -------------------------------------*/
  else
  {
    /* Send the data read from the memory */
    SPI_I2S_SendData(SPI2, (Media_ReadHalfWord(AudioDataIndex)));

    /* Increment the index */
    IncrementVar_AudioDataIndex(WAVE_Format.NumChannels); 

    /* Check and update the stream playing status */
    I2S_CODEC_UpdateStatus();
  } 
}

/**
  * @brief  Inserts a delay time.
  * @param  nCount: specifies the delay time length
  * @retval The length of the wave file read from the SPI_Flash
  */
void delay(__IO uint32_t nCount)
{
  for (; nCount != 0; nCount--);
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
