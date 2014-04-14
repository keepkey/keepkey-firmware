/**
  ******************************************************************************
  * @file    smartcard.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   This file provides all the Smartcard firmware functions.
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
#include "smartcard.h"

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Global variables definition and initialization ----------------------------*/
SC_ATR SC_A2R;
static uint8_t SC_ATR_Table[40];
static __IO uint8_t SCData = 0;
static uint32_t F_Table[16] = {0, 372, 558, 744, 1116, 1488, 1860, 0,
                          0, 512, 768, 1024, 1536, 2048, 0, 0};
static uint32_t D_Table[8] = {0, 1, 2, 4, 8, 16, 0, 0};

/* Private function prototypes -----------------------------------------------*/
/* Transport Layer -----------------------------------------------------------*/
/*--------------APDU-----------*/
static void SC_SendData(SC_ADPU_Commands *SC_ADPU, SC_ADPU_Responce *SC_ResponceStatus);

/*------------ ATR ------------*/
static void SC_AnswerReq(SC_State *SCState, uint8_t *card, uint8_t length);  /* Ask ATR */
static uint8_t SC_decode_Answer2reset(uint8_t *card);  /* Decode ATR */

/* Physical Port Layer -------------------------------------------------------*/
static void SC_Init(void);
static void SC_DeInit(void);
static void SC_VoltageConfig(uint32_t SC_Voltage);
static uint8_t SC_Detect(void);
static ErrorStatus USART_ByteReceive(uint8_t *Data, uint32_t TimeOut);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Handles all Smartcard states and serves to send and receive all
  *         communication data between Smartcard and reader.
  * @param  SCState: pointer to an SC_State enumeration that will contain
  *         the Smartcard state.
  * @param  SC_ADPU: pointer to an SC_ADPU_Commands structure that will be
  *         initialized.
  * @param  SC_Response: pointer to a SC_ADPU_Responce structure which will
  *         be initialized.
  * @retval None
  */
void SC_Handler(SC_State *SCState, SC_ADPU_Commands *SC_ADPU, SC_ADPU_Responce *SC_Response)
{
  uint32_t i = 0;

  switch(*SCState)
  {
    case SC_POWER_ON:
      if (SC_ADPU->Header.INS == SC_GET_A2R)
      {
        /* Smartcard intialization ------------------------------------------*/
        SC_Init();

        /* Reset Data from SC buffer -----------------------------------------*/
        for (i = 0; i < 40; i++)
        {
          SC_ATR_Table[i] = 0;
        }
        
        /* Reset SC_A2R Structure --------------------------------------------*/
        SC_A2R.TS = 0;
        SC_A2R.T0 = 0;
        for (i = 0; i < SETUP_LENGTH; i++)
        {
          SC_A2R.T[i] = 0;
        }
        for (i = 0; i < HIST_LENGTH; i++)
        {
          SC_A2R.H[i] = 0;
        }
        SC_A2R.Tlength = 0;
        SC_A2R.Hlength = 0;
        
        /* Next State --------------------------------------------------------*/
        *SCState = SC_RESET_LOW;
      }
    break;

    case SC_RESET_LOW:
      if(SC_ADPU->Header.INS == SC_GET_A2R)
      {
        /* If card is detected then Power ON, Card Reset and wait for an answer) */
        if (SC_Detect())
        {
          while(((*SCState) != SC_POWER_OFF) && ((*SCState) != SC_ACTIVE))
          {
            SC_AnswerReq(SCState, &SC_ATR_Table[0], 40); /* Check for answer to reset */
          }
        }
        else
        {
          (*SCState) = SC_POWER_OFF;
        } 
      }
    break;

    case SC_ACTIVE:
      if (SC_ADPU->Header.INS == SC_GET_A2R)
      {
        if(SC_decode_Answer2reset(&SC_ATR_Table[0]) == T0_PROTOCOL)
        {
          (*SCState) = SC_ACTIVE_ON_T0;
        }
        else
        {
          (*SCState) = SC_POWER_OFF; 
        }
      }
    break;

    case SC_ACTIVE_ON_T0:
      SC_SendData(SC_ADPU, SC_Response);
    break;

    case SC_POWER_OFF:
      SC_DeInit(); /* Disable Smartcard interface */
    break;

    default: (*SCState) = SC_POWER_OFF;
  }
}

/**
  * @brief  Enables or disables the power to the Smartcard.
  * @param  NewState: new state of the Smartcard power supply. 
  *                   This parameter can be: ENABLE or DISABLE.
  * @retval None
  */
void SC_PowerCmd(FunctionalState NewState)
{
  if(NewState != DISABLE)
  {
    GPIO_SetBits(GPIO_CMDVCC, SC_CMDVCC);
  }
  else
  {
    GPIO_ResetBits(GPIO_CMDVCC, SC_CMDVCC);
  } 
}

/**
  * @brief  Sets or clears the Smartcard reset pin.
  * @param  ResetState: this parameter specifies the state of the Smartcard 
  *         reset pin.
  * @param  BitVal must be one of the BitAction enum values:
  *         - Bit_RESET: to clear the port pin.
  *         - Bit_SET: to set the port pin.
  * @retval None
  */
void SC_Reset(BitAction ResetState)
{
  GPIO_WriteBit(GPIO_RESET, SC_RESET, ResetState);
}

/**
  * @brief  Resends the byte that failed to be received (by the Smartcard)
  *         correctly.
  * @param  None
  * @retval None
  */
void SC_ParityErrorHandler(void)
{
  USART_SendData(USART3, SCData);
  while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
  {
  } 
}

/**
  * @brief  Configures the IO speed (BaudRate) communication.
  * @param  None
  * @retval None
  */
void SC_PTSConfig(void)
{
  RCC_ClocksTypeDef RCC_ClocksStatus;
  uint32_t workingbaudrate = 0, apbclock = 0;
  uint8_t locData = 0, PTSConfirmStatus = 1;
  USART_InitTypeDef USART_InitStructure;
  USART_ClockInitTypeDef USART_ClockInitStructure;

  /* Reconfigure the USART Baud Rate -------------------------------------------*/
  RCC_GetClocksFreq(&RCC_ClocksStatus);
  apbclock = RCC_ClocksStatus.PCLK1_Frequency;
  apbclock /= ((USART3->GTPR & (uint16_t)0x00FF) * 2);

  /* Enable the DMA Receive (Set DMAR bit only) to enable interrupt generation
     in case of a framing error FE */  
  USART_DMACmd(USART3, USART_DMAReq_Rx, ENABLE);
  
  if((SC_A2R.T0 & (uint8_t)0x10) == 0x10)
  {
    if(SC_A2R.T[0] != 0x11)
    {
      /* Send PTSS */
      SCData = 0xFF;
      USART_SendData(USART3, SCData);
      while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
      {
      }

      /* Send PTS0 */
      SCData = 0x10;
      USART_SendData(USART3, SCData);
      while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
      {
      }

      /* Send PTS1 */
      SCData = SC_A2R.T[0]; 
      USART_SendData(USART3, SCData);
      while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
      {
      }

      /* Send PCK */
      SCData = (uint8_t)0xFF^(uint8_t)0x10^(uint8_t)SC_A2R.T[0]; 
      USART_SendData(USART3, SCData);
      while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
      {
      }

      /* Disable the DMA Receive (Reset DMAR bit only) */  
      USART_DMACmd(USART3, USART_DMAReq_Rx, DISABLE);

      if((USART_ByteReceive(&locData, SC_Receive_Timeout)) == SUCCESS)
      {
        if(locData != 0xFF)
        {
           PTSConfirmStatus = 0x00;
        }
      }
      if((USART_ByteReceive(&locData, SC_Receive_Timeout)) == SUCCESS)
      {
        if(locData != 0x10)
        {
           PTSConfirmStatus = 0x00;
        }
      }
      if((USART_ByteReceive(&locData, SC_Receive_Timeout)) == SUCCESS)
      {
        if(locData != SC_A2R.T[0])
        {
           PTSConfirmStatus = 0x00;
        }
      }
      if((USART_ByteReceive(&locData, SC_Receive_Timeout)) == SUCCESS)
      {
        if(locData != ((uint8_t)0xFF^(uint8_t)0x10^(uint8_t)SC_A2R.T[0]))
        {
           PTSConfirmStatus = 0x00;
        }
      }
      else
      {
        PTSConfirmStatus = 0x00;
      }
      /* PTS Confirm */
      if(PTSConfirmStatus == 0x01)
      {
        workingbaudrate = apbclock * D_Table[(SC_A2R.T[0] & (uint8_t)0x0F)];
        workingbaudrate /= F_Table[((SC_A2R.T[0] >> 4) & (uint8_t)0x0F)];

        USART_ClockInitStructure.USART_Clock = USART_Clock_Enable;
        USART_ClockInitStructure.USART_CPOL = USART_CPOL_Low;
        USART_ClockInitStructure.USART_CPHA = USART_CPHA_1Edge;
        USART_ClockInitStructure.USART_LastBit = USART_LastBit_Enable;
        USART_ClockInit(USART3, &USART_ClockInitStructure);

        USART_InitStructure.USART_BaudRate = workingbaudrate;
        USART_InitStructure.USART_WordLength = USART_WordLength_9b;
        USART_InitStructure.USART_StopBits = USART_StopBits_1_5;
        USART_InitStructure.USART_Parity = USART_Parity_Even;
        USART_InitStructure.USART_Mode = USART_Mode_Rx | USART_Mode_Tx;
        USART_InitStructure.USART_HardwareFlowControl = USART_HardwareFlowControl_None;
        USART_Init(USART3, &USART_InitStructure);
      }
    }
  }  
}

/**
  * @brief  Manages the Smartcard transport layer: send APDU commands and receives
  *         the APDU responce.
  * @param  SC_ADPU: pointer to a SC_ADPU_Commands structure which will be 
  *         initialized
  * @param  SC_Response: pointer to a SC_ADPU_Responce structure which will be 
  *         initialized.
  * @retval None
  */
static void SC_SendData(SC_ADPU_Commands *SC_ADPU, SC_ADPU_Responce *SC_ResponceStatus)
{
  uint32_t i = 0;
  uint8_t locData = 0;

  /* Reset responce buffer ---------------------------------------------------*/
  for(i = 0; i < LCmax; i++)
  {
    SC_ResponceStatus->Data[i] = 0;
  }
  
  SC_ResponceStatus->SW1 = 0;
  SC_ResponceStatus->SW2 = 0;

  /* Enable the DMA Receive (Set DMAR bit only) to enable interrupt generation
     in case of a framing error FE */  
  USART_DMACmd(USART3, USART_DMAReq_Rx, ENABLE);

  /* Send header -------------------------------------------------------------*/
  SCData = SC_ADPU->Header.CLA;
  USART_SendData(USART3, SCData);
  while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
  {
  }  
  
  SCData = SC_ADPU->Header.INS;
  USART_SendData(USART3, SCData);
  while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
  {
  }
   
  SCData = SC_ADPU->Header.P1;
  USART_SendData(USART3, SCData);
  while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
  {
  } 
  
  SCData = SC_ADPU->Header.P2;
  USART_SendData(USART3, SCData);
  while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
  {
  }

  /* Send body length to/from SC ---------------------------------------------*/
  if(SC_ADPU->Body.LC)
  {
    SCData = SC_ADPU->Body.LC;
    USART_SendData(USART3, SCData);
    while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
    {
    }
  }
  else if(SC_ADPU->Body.LE)
  { 
    SCData = SC_ADPU->Body.LE;
    USART_SendData(USART3, SCData);
    while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
    {
    }
  }
  /* Flush the USART3 DR */
  (void)USART_ReceiveData(USART3);

  /* --------------------------------------------------------
    Wait Procedure byte from card:
    1 - ACK
    2 - NULL
    3 - SW1; SW2
   -------------------------------------------------------- */

  if((USART_ByteReceive(&locData, SC_Receive_Timeout)) == SUCCESS)
  {
    if(((locData & (uint8_t)0xF0) == 0x60) || ((locData & (uint8_t)0xF0) == 0x90))
    {
      /* SW1 received */
      SC_ResponceStatus->SW1 = locData;

      if((USART_ByteReceive(&locData, SC_Receive_Timeout)) == SUCCESS)
      {
        /* SW2 received */
        SC_ResponceStatus->SW2 = locData;
      }
    }
    else if (((locData & (uint8_t)0xFE) == (((uint8_t)~(SC_ADPU->Header.INS)) & (uint8_t)0xFE))||((locData & (uint8_t)0xFE) == (SC_ADPU->Header.INS & (uint8_t)0xFE)))
    {
      SC_ResponceStatus->Data[0] = locData;/* ACK received */
    }
  }

  /* If no status bytes received ---------------------------------------------*/
  if(SC_ResponceStatus->SW1 == 0x00)
  {
    /* Send body data to SC--------------------------------------------------*/
    if (SC_ADPU->Body.LC)
    {
      for(i = 0; i < SC_ADPU->Body.LC; i++)
      {
        SCData = SC_ADPU->Body.Data[i];
        
        USART_SendData(USART3, SCData);
        while(USART_GetFlagStatus(USART3, USART_FLAG_TC) == RESET)
        {
        }
      }
      /* Flush the USART3 DR */
      (void)USART_ReceiveData(USART3);
      /* Disable the DMA Receive (Reset DMAR bit only) */  
      USART_DMACmd(USART3, USART_DMAReq_Rx, DISABLE);
    }

    /* Or receive body data from SC ------------------------------------------*/
    else if (SC_ADPU->Body.LE)
    {
      for(i = 0; i < SC_ADPU->Body.LE; i++)
      {
        if(USART_ByteReceive(&locData, SC_Receive_Timeout) == SUCCESS)
        {
          SC_ResponceStatus->Data[i] = locData;
        }
      }
    }
    /* Wait SW1 --------------------------------------------------------------*/
    i = 0;
    while(i < 10)
    {
      if(USART_ByteReceive(&locData, SC_Receive_Timeout) == SUCCESS)
      {
        SC_ResponceStatus->SW1 = locData;
        i = 11;
      }
      else
      {
        i++;
      }
    }
    /* Wait SW2 ------------------------------------------------------------*/   
    i = 0;
    while(i < 10)
    {
      if(USART_ByteReceive(&locData, SC_Receive_Timeout) == SUCCESS)
      {
        SC_ResponceStatus->SW2 = locData;
        i = 11;
      }
      else
      {
        i++;
      }
    }
  }
}

/**
  * @brief  Requests the reset answer from card.
  * @param  SCState: pointer to an SC_State enumeration that will contain
  *         the Smartcard state.
  * @param  *card: pointer to a buffer which will contain the card ATR.
  * @param  length: maximum ATR length
  * @retval None
  */
static void SC_AnswerReq(SC_State *SCstate, uint8_t *card, uint8_t length)
{
  uint8_t Data = 0;
  uint32_t i = 0;

  switch(*SCstate)
  {
    case SC_RESET_LOW:
      /* Check responce with reset low ---------------------------------------*/
      for (i = 0; i < length; i++)
      {
        if((USART_ByteReceive(&Data, SC_Receive_Timeout)) == SUCCESS)
        {
          card[i] = Data;
        }
      }
      if(card[0])
      {
        (*SCstate) = SC_ACTIVE;
        SC_Reset(Bit_SET);
      }
      else
      {
        (*SCstate) = SC_RESET_HIGH;
      }
    break;

    case SC_RESET_HIGH:
      /* Check responce with reset high --------------------------------------*/
      SC_Reset(Bit_SET); /* Reset High */
  
      while(length--)
      {
        if((USART_ByteReceive(&Data, SC_Receive_Timeout)) == SUCCESS)
        {
          *card++ = Data; /* Receive data for timeout = SC_Receive_Timeout */
        }       
      }
      if(card[0])
      {
        (*SCstate) = SC_ACTIVE;
      }
      else
      {
        (*SCstate) = SC_POWER_OFF;
      }
    break;

    case SC_ACTIVE:
    break;
    
    case SC_POWER_OFF:
      /* Close Connection if no answer received ------------------------------*/
      SC_Reset(Bit_SET); /* Reset high - a bit is used as level shifter from 3.3 to 5 V */
      SC_PowerCmd(DISABLE);
    break;

    default:
      (*SCstate) = SC_RESET_LOW;
  }
}

/**
  * @brief  Decodes the Answer to reset received from card.
  * @param  *card: pointer to a buffer which will contain the card ATR.
  * @retval None
  */
static uint8_t SC_decode_Answer2reset(uint8_t *card)
{
  uint32_t i = 0, flag = 0, buf = 0, protocol = 0;

  SC_A2R.TS = card[0];  /* Initial character */
  SC_A2R.T0 = card[1];  /* Format character */

  SC_A2R.Hlength = SC_A2R.T0 & (uint8_t)0x0F;

  if ((SC_A2R.T0 & (uint8_t)0x80) == 0x80)
  {
    flag = 1;
  }

  for (i = 0; i < 4; i++)
  {
    SC_A2R.Tlength = SC_A2R.Tlength + (((SC_A2R.T0 & (uint8_t)0xF0) >> (4 + i)) & (uint8_t)0x1);
  }

  for (i = 0; i < SC_A2R.Tlength; i++)
  {
    SC_A2R.T[i] = card[i + 2];
  }

  protocol = SC_A2R.T[SC_A2R.Tlength - 1] & (uint8_t)0x0F;

  while (flag)
  {
    if ((SC_A2R.T[SC_A2R.Tlength - 1] & (uint8_t)0x80) == 0x80)
    {
      flag = 1;
    }
    else
    {
      flag = 0;
    }

    buf = SC_A2R.Tlength;
    SC_A2R.Tlength = 0;

    for (i = 0; i < 4; i++)
    {
      SC_A2R.Tlength = SC_A2R.Tlength + (((SC_A2R.T[buf - 1] & (uint8_t)0xF0) >> (4 + i)) & (uint8_t)0x1);
    }
	
    for (i = 0;i < SC_A2R.Tlength; i++)
    {
      SC_A2R.T[buf + i] = card[i + 2 + buf];
    }
    SC_A2R.Tlength += (uint8_t)buf;
  }

  for (i = 0; i < SC_A2R.Hlength; i++)
  {
    SC_A2R.H[i] = card[i + 2 + SC_A2R.Tlength];
  }

  return (uint8_t)protocol;
}

/**
  * @brief  Initializes all peripheral used for Smartcard interface.
  * @param  None
  * @retval None
  */
static void SC_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStructure;
  USART_InitTypeDef USART_InitStructure;
  USART_ClockInitTypeDef USART_ClockInitStructure;  
  
  /* Enable GPIO_3_5V, GPIORESET and GPIO_CMDVCC clocks */
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_3_5V | RCC_APB2Periph_RESET |
                         RCC_APB2Periph_CMDVCC, ENABLE);
                         
  /* Enable USART3 clock */
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, ENABLE);
                           
  /* Configure USART3 CK(PB.12) as alternate function push-pull */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_12;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_PP;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_Init(GPIOB, &GPIO_InitStructure);
  
  /* Configure USART3 Tx (PB.10) as alternate function open-drain */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_OD;
  GPIO_Init(GPIOB, &GPIO_InitStructure);

  /* Configure Smartcard Reset  */
  GPIO_InitStructure.GPIO_Pin = SC_RESET;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
  GPIO_Init(GPIO_RESET, &GPIO_InitStructure);

  /* Configure Smartcard 3/5V  */
  GPIO_InitStructure.GPIO_Pin = SC_3_5V;
  GPIO_Init(GPIO_3_5V, &GPIO_InitStructure);

  /* Configure Smartcard CMDVCC  */
  GPIO_InitStructure.GPIO_Pin = SC_CMDVCC;
  GPIO_Init(GPIO_CMDVCC, &GPIO_InitStructure);
    
/* USART3 configuration ------------------------------------------------------*/
  /* USART3 configured as follow:
        - Word Length = 9 Bits
        - 0.5 Stop Bit
        - Even parity
        - BaudRate = 9677 baud
        - Hardware flow control disabled (RTS and CTS signals)
        - Tx and Rx enabled
        - USART Clock enabled
  */

  /* USART Clock set to 3.6 MHz (PCLK1 (36 MHZ) / 10) */
  USART_SetPrescaler(USART3, 0x05);
  
  /* USART Guard Time set to 16 Bit */
  USART_SetGuardTime(USART3, 16);
  
  USART_ClockInitStructure.USART_Clock = USART_Clock_Enable;
  USART_ClockInitStructure.USART_CPOL = USART_CPOL_Low;
  USART_ClockInitStructure.USART_CPHA = USART_CPHA_1Edge;
  USART_ClockInitStructure.USART_LastBit = USART_LastBit_Enable;
  USART_ClockInit(USART3, &USART_ClockInitStructure);


  USART_InitStructure.USART_BaudRate = 9677;
  USART_InitStructure.USART_WordLength = USART_WordLength_9b;
  USART_InitStructure.USART_StopBits = USART_StopBits_1_5;
  USART_InitStructure.USART_Parity = USART_Parity_Even;
  USART_InitStructure.USART_Mode = USART_Mode_Rx | USART_Mode_Tx;
  USART_InitStructure.USART_HardwareFlowControl = USART_HardwareFlowControl_None;
  USART_Init(USART3, &USART_InitStructure); 

  /* Enable the USART3 Parity Error Interrupt */
  USART_ITConfig(USART3, USART_IT_PE, ENABLE);

  /* Enable the USART3 Framing Error Interrupt */
  USART_ITConfig(USART3, USART_IT_ERR, ENABLE);

  /* Enable USART3 */
  USART_Cmd(USART3, ENABLE);

  /* Enable the NACK Transmission */
  USART_SmartCardNACKCmd(USART3, ENABLE);

  /* Enable the Smartcard Interface */
  USART_SmartCardCmd(USART3, ENABLE);
  
  /* Set RSTIN HIGH */  
  SC_Reset(Bit_SET);
  
  /* Select 5V */ 
  SC_VoltageConfig(SC_Voltage_5V);
  
  /* Disable CMDVCC */
  SC_PowerCmd(DISABLE);
}

/**
  * @brief  Deinitializes all ressources used by the Smartcard interface.
  * @param  None
  * @retval None
  */
static void SC_DeInit(void)
{
  /* Disable CMDVCC */
  SC_PowerCmd(ENABLE);

  /* Deinitializes the USART3 */
  USART_DeInit(USART3);

  /* Deinitializes the GPIO_3_5V */
  GPIO_DeInit(GPIO_3_5V);

  /* Deinitializes the GPIO_RESET */
  GPIO_DeInit(GPIO_RESET);

  /* Deinitializes the GPIO_CMDVCC */
  GPIO_DeInit(GPIO_CMDVCC);

  /* Disable GPIO_3_5V, GPIO_RESET and GPIO_CMDVCC clocks */
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_3_5V | RCC_APB2Periph_RESET 
                         | RCC_APB2Periph_CMDVCC, DISABLE);
                         
  /* Disable USART3 clock */
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, DISABLE);
}

/**
  * @brief  Configures the card power voltage.
  * @param  SC_Voltage: specifies the card power voltage.
  *         This parameter can be one of the following values:
  *           - SC_Voltage_5V: 5V cards.
  *           - SC_Voltage_3V: 3V cards.
  * @retval None
  */
static void SC_VoltageConfig(uint32_t SC_Voltage)
{
  if(SC_Voltage == SC_Voltage_5V)
  {
    /* Select Smartcard 5V */  
    GPIO_SetBits(GPIO_3_5V, SC_3_5V);
  }
  else
  {
    /* Select Smartcard 3V */      
    GPIO_ResetBits(GPIO_3_5V, SC_3_5V);
  } 
}

/**
  * @brief  Detects whether the Smartcard is present or not.
  * @param  None
  * @retval 0 - Smartcard inserted
  *         1 - Smartcard not inserted
  */
static uint8_t SC_Detect(void)
{
  return GPIO_ReadInputDataBit(GPIO_OFF, SC_OFF);
}

/**
  * @brief  Receives a new data while the time out not elapsed.
  * @param  None
  * @retval An ErrorStatus enumuration value:
  *          - SUCCESS: New data has been received
  *          - ERROR: time out was elapsed and no further data is received
  */
static ErrorStatus USART_ByteReceive(uint8_t *Data, uint32_t TimeOut)
{
  uint32_t Counter = 0;

  while((USART_GetFlagStatus(USART3, USART_FLAG_RXNE) == RESET) && (Counter != TimeOut))
  {
    Counter++;
  }

  if(Counter != TimeOut)
  {
    *Data = (uint8_t)USART_ReceiveData(USART3);
    return SUCCESS;    
  }
  else 
  {
    return ERROR;
  }
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
