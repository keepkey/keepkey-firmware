/**
  ******************************************************************************
  * @file    mass_mal.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   Medium Access Layer interface.
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
#include "platform_config.h"
#include "mass_mal.h"

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
uint32_t Mass_Memory_Size[2];
uint32_t Mass_Block_Size[2];
uint32_t Mass_Block_Count[2];
__IO uint32_t Status = 0;

SD_CardInfo mSDCardInfo;


/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Initializes the Media on the STM32
  * @param  None
  * @retval None
  */
uint16_t MAL_Init(uint8_t lun)
{
  uint16_t status = MAL_OK;

  switch (lun)
  {
    case 0:
      Status = SD_Init();
      break;
    case 1:
      NAND_Init();
      break;
    default:
      return MAL_FAIL;
  }
  return status;
}

/**
  * @brief  Write sectors
  * @param  None
  * @retval None
  */
uint16_t MAL_Write(uint8_t lun, uint32_t Memory_Offset, uint32_t *Writebuff, uint16_t Transfer_Length)
{

  switch (lun)
  {
    case 0:
    Status = SD_WriteMultiBlocks((uint8_t*)Writebuff, Memory_Offset, Transfer_Length,1);
    Status = SD_WaitWriteOperation();  
   
    while(SD_GetStatus() != SD_TRANSFER_OK);
      if ( Status != SD_OK )
      {
        return MAL_FAIL;
      }      
      break;
    case 1:
      NAND_Write(Memory_Offset, Writebuff, Transfer_Length);
      break;
    default:
      return MAL_FAIL;
  }
  return MAL_OK;
}

/**
  * @brief  Read sectors
  * @param  None
  * @retval Buffer pointer
  */
uint16_t MAL_Read(uint8_t lun, uint32_t Memory_Offset, uint32_t *Readbuff, uint16_t Transfer_Length)
{

  switch (lun)
  {
    case 0:

      SD_ReadMultiBlocks((uint8_t*)Readbuff, Memory_Offset, Transfer_Length, 1);
      Status = SD_WaitReadOperation();
      while(SD_GetStatus() != SD_TRANSFER_OK)
      {
      }
      
      if ( Status != SD_OK )
      {
        return MAL_FAIL;
      }

      break;
    case 1:
      NAND_Read(Memory_Offset, Readbuff, Transfer_Length);
      ;
      break;
    default:
      return MAL_FAIL;
  }
  return MAL_OK;
}

/**
  * @brief  Get status
  * @param  None
  * @retval None
  */
uint16_t MAL_GetStatus (uint8_t lun)
{
  NAND_IDTypeDef NAND_ID;
  uint32_t DeviceSizeMul = 0, NumberOfBlocks = 0;

  if (lun == 0)
  {
    if (SD_Init() == SD_OK)
    {
      SD_GetCardInfo(&mSDCardInfo);
      SD_SelectDeselect((uint32_t) (mSDCardInfo.RCA << 16));
      DeviceSizeMul = (mSDCardInfo.SD_csd.DeviceSizeMul + 2);

      if(mSDCardInfo.CardType == SDIO_HIGH_CAPACITY_SD_CARD)
      {
        Mass_Block_Count[0] = (mSDCardInfo.SD_csd.DeviceSize + 1) * 1024;
      }
      else
      {
        NumberOfBlocks  = ((1 << (mSDCardInfo.SD_csd.RdBlockLen)) / 512);
        Mass_Block_Count[0] = ((mSDCardInfo.SD_csd.DeviceSize + 1) * (1 << DeviceSizeMul) << (NumberOfBlocks/2));
      }
      Mass_Block_Size[0]  = 512;

      Status = SD_SelectDeselect((uint32_t) (mSDCardInfo.RCA << 16)); 
      Status = SD_EnableWideBusOperation(SDIO_BusWide_4b); 
      if ( Status != SD_OK )
      {
        return MAL_FAIL;
      }

      Mass_Memory_Size[0] = Mass_Block_Count[0] * Mass_Block_Size[0];
      STM_EVAL_LEDOn(LED2);
      return MAL_OK;
    }
  }
  else
  {
    NAND_ReadID(&NAND_ID);
    if (NAND_ID.Device_ID != 0 )
    {
      /* only one zone is used */
      Mass_Block_Count[1] = NAND_ZONE_SIZE * NAND_BLOCK_SIZE * NAND_MAX_ZONE ;
      Mass_Block_Size[1]  = NAND_PAGE_SIZE;
      Mass_Memory_Size[1] = (Mass_Block_Count[1] * Mass_Block_Size[1]);
      return MAL_OK;
    }
  }
  STM_EVAL_LEDOn(LED2);
  return MAL_FAIL;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
