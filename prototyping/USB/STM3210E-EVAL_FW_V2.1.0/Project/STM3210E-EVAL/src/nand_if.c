/**
  ******************************************************************************
  * @file    nand_if.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   manage NAND operationx state machine
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
#include "nand_if.h"
#include "mass_mal.h"
#include "stm3210e_eval_fsmc_nand.h"
#include "memory.h"

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* extern variables-----------------------------------------------------------*/
extern uint32_t SCSI_LBA;
extern uint32_t SCSI_BlkLen;
/* Private variables ---------------------------------------------------------*/
uint16_t LUT[1024]; /* Look Up Table Buffer */
WRITE_STATE Write_State;
BLOCK_STATE Block_State;
NAND_ADDRESS wAddress, fAddress;
uint16_t  phBlock, LogAddress, Initial_Page, CurrentZone = 0;
uint16_t  Written_Pages = 0;

uint16_t LUT[1024]; /* Look Up Table Buffer */

/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/
static uint16_t NAND_CleanLUT(uint8_t ZoneNbr);
static NAND_ADDRESS NAND_GetAddress(uint32_t Address);
static uint16_t NAND_GetFreeBlock(void);
static uint16_t NAND_Write_Cleanup(void);
SPARE_AREA ReadSpareArea(uint32_t address);
static uint16_t NAND_Copy(NAND_ADDRESS Address_Src, NAND_ADDRESS Address_Dest, uint16_t PageToCopy);
static NAND_ADDRESS NAND_ConvertPhyAddress(uint32_t Address);
static uint16_t NAND_BuildLUT(uint8_t ZoneNbr);

/**
  * @brief  Init NAND Interface.
  * @param  None
  * @retval Status
  */
uint16_t Demo_NAND_Init(void)
{
  uint16_t Status = NAND_OK;

  NAND_Init();
  Status = NAND_BuildLUT(0);
  Write_State = WRITE_IDLE;
  return Status;
}

/**
  * @brief  write one sector by once.
  * @param  Memory_Offset
  * @param  *Writebuff
  * @param  Transfer_Length
  * @retval Status
  */
uint16_t NAND_Write(uint32_t Memory_Offset, uint32_t *Writebuff, uint16_t Transfer_Length)
{
  /* check block status and calculate start and end addreses */
  wAddress    = NAND_GetAddress(Memory_Offset / 512);

  /*check Zone: if second zone is requested build second LUT*/
  if (wAddress.Zone != CurrentZone)
  {
    CurrentZone = wAddress.Zone;
    NAND_BuildLUT(CurrentZone);
  }

  phBlock     = LUT[wAddress.Block]; /* Block Index + flags */
  LogAddress  = wAddress.Block ; /* save logical block */

  /*  IDLE state  */
  /****************/
  if ( Write_State == WRITE_IDLE)
  {/* Idle state */

    if (phBlock & USED_BLOCK)
    { /* USED BLOCK */

      Block_State = OLD_BLOCK;
      /* Get a free Block for swap */
      fAddress.Block = NAND_GetFreeBlock();
      fAddress.Zone  = wAddress.Zone;
      Initial_Page = fAddress.Page  = wAddress.Page;

      /* write the new page */
      NAND_WriteSmallPage((uint8_t *)Writebuff, fAddress, PAGE_TO_WRITE);
      Written_Pages++;

      /* get physical block */
      wAddress.Block = phBlock & 0x3FF;

      if (Written_Pages == SCSI_BlkLen)
      {
        NAND_Write_Cleanup();
        Written_Pages = 0;
        return NAND_OK;
      }
      else
      {
        if (wAddress.Page == (NAND_BLOCK_SIZE - 1))
        {
          NAND_Write_Cleanup();
          return NAND_OK;
        }
        Write_State = WRITE_ONGOING;
        return NAND_OK;
      }
    }
    else
    {/* UNUSED BLOCK */

      Block_State = UNUSED_BLOCK;
      /* write the new page */
      wAddress.Block = phBlock & 0x3FF;
      NAND_WriteSmallPage( (uint8_t *)Writebuff , wAddress, PAGE_TO_WRITE);

      Written_Pages++;
      if (Written_Pages == SCSI_BlkLen)
      {
        Written_Pages = 0;
        NAND_Write_Cleanup();
        return NAND_OK;
      }
      else
      {
        Write_State = WRITE_ONGOING;
        return NAND_OK;
      }
    }
  }
  /* WRITE state */
  /***************/
  if ( Write_State == WRITE_ONGOING)
  {/* Idle state */
    if (phBlock & USED_BLOCK)
    { /* USED BLOCK */

      wAddress.Block = phBlock & 0x3FF;
      Block_State = OLD_BLOCK;
      fAddress.Page  = wAddress.Page;

      /* check if next pages are in next block */
      if (wAddress.Page == (NAND_BLOCK_SIZE - 1))
      {
        /* write Last page  */
        NAND_WriteSmallPage( (uint8_t *)Writebuff , fAddress, PAGE_TO_WRITE);
        Written_Pages++;
        if (Written_Pages == SCSI_BlkLen)
        {
          Written_Pages = 0;
        }
        /* Clean up and Update the LUT */
        NAND_Write_Cleanup();
        Write_State = WRITE_IDLE;
        return NAND_OK;
      }

      /* write next page */
      NAND_WriteSmallPage( (uint8_t *)Writebuff , fAddress, PAGE_TO_WRITE);
      Written_Pages++;
      if (Written_Pages == SCSI_BlkLen)
      {
        Write_State = WRITE_IDLE;
        NAND_Write_Cleanup();
        Written_Pages = 0;
      }

    }
    else
    {/* UNUSED BLOCK */
      wAddress.Block = phBlock & 0x3FF;
      /* check if it is the last page in prev block */
      if (wAddress.Page == (NAND_BLOCK_SIZE - 1))
      {
        /* write Last page  */
        NAND_WriteSmallPage( (uint8_t *)Writebuff , wAddress, PAGE_TO_WRITE);
        Written_Pages++;
        if (Written_Pages == SCSI_BlkLen)
        {
          Written_Pages = 0;
        }

        /* Clean up and Update the LUT */
        NAND_Write_Cleanup();
        Write_State = WRITE_IDLE;

        return NAND_OK;
      }
      /* write next page in same block */
      NAND_WriteSmallPage( (uint8_t *)Writebuff , wAddress, PAGE_TO_WRITE);
      Written_Pages++;
      if (Written_Pages == SCSI_BlkLen)
      {
        Write_State = WRITE_IDLE;
        NAND_Write_Cleanup();
        Written_Pages = 0;
      }
    }
  }
  return NAND_OK;
}

/**
  * @brief  Read sectors.
  * @param  Memory_Offset
  * @param  *Readbuff
  * @param  Transfer_Length
  * @retval Status
  */
uint16_t NAND_Read(uint32_t Memory_Offset, uint32_t *Readbuff, uint16_t Transfer_Length)
{
  NAND_ADDRESS phAddress;

  phAddress = NAND_GetAddress(Memory_Offset / 512);

  if (phAddress.Zone != CurrentZone)
  {
    CurrentZone = phAddress.Zone;
    NAND_BuildLUT(CurrentZone);
  }

  if (LUT [phAddress.Block] & BAD_BLOCK)
  {
    return NAND_FAIL;
  }
  else
  {
    phAddress.Block = LUT [phAddress.Block] & ~ (USED_BLOCK | VALID_BLOCK);
    NAND_ReadSmallPage( (uint8_t *)Readbuff , phAddress, Transfer_Length / 512);
  }
  return NAND_OK;
}

/**
  * @brief  Erase old blocks & rebuild the look up table.
  * @param  ZoneNbr
  * @retval Status
  */
static uint16_t NAND_CleanLUT (uint8_t ZoneNbr)
{
#ifdef WEAR_LEVELLING_SUPPORT
  uint16_t BlockIdx, LUT_Item;
#endif
  /* Rebuild the LUT for the current zone */
  NAND_BuildLUT (ZoneNbr);

#ifdef WEAR_LEVELLING_SUPPORT
  /* Wear Leveling : circular use of free blocks */
  LUT_Item = LUT [BlockIdx]
             for (BlockIdx == MAX_LOG_BLOCKS_PER_ZONE ; BlockIdx < MAX_LOG_BLOCKS_PER_ZONE + WEAR_DEPTH ; BlockIdx++)
             {
               LUT [BlockIdx] = LUT [BlockIdx + 1];
             }
             LUT [ MAX_LOG_BLOCKS_PER_ZONE + WEAR_DEPTH - 1] = LUT_Item ;
#endif

  return NAND_OK;
}

/**
  * @brief  Translate logical address into a phy one.
  * @param  Address
  * @retval Status
  */
static NAND_ADDRESS NAND_GetAddress (uint32_t Address)
{
  NAND_ADDRESS Address_t;

  Address_t.Page  = Address & (NAND_BLOCK_SIZE - 1);
  Address_t.Block = Address / NAND_BLOCK_SIZE;
  Address_t.Zone = 0;

  while (Address_t.Block >= MAX_LOG_BLOCKS_PER_ZONE)
  {
    Address_t.Block -= MAX_LOG_BLOCKS_PER_ZONE;
    Address_t.Zone++;
  }
  return Address_t;
}

/**
  * @brief  Look for a free block for data exchange.
  * @param  None
  * @retval Status
  */
static uint16_t NAND_GetFreeBlock (void)
{
  return LUT[MAX_LOG_BLOCKS_PER_ZONE]& ~(USED_BLOCK | VALID_BLOCK);
}

/**
  * @brief  Check used block.
  * @param  address
  * @retval Status
  */
SPARE_AREA ReadSpareArea (uint32_t address)
{
  SPARE_AREA t;
  uint8_t Buffer[16];
  NAND_ADDRESS address_s;
  address_s = NAND_ConvertPhyAddress(address);
  NAND_ReadSpareArea(Buffer , address_s, 1) ;

  t.LogicalIndex = (uint16_t)((uint16_t)Buffer[0] | (uint16_t)Buffer[1]<< 8);
  t.DataStatus = (uint16_t)((uint16_t)Buffer[2] | (uint16_t)Buffer[3]<< 8);
  t.BlockStatus = (uint16_t)((uint16_t)Buffer[4] | (uint16_t)Buffer[5]<< 8);

  return t;
}

/**
  * @brief  NAND Copy page
  * @param  Address_Src
  * @param  Address_Dest
  * @param  PageToCopy
  * @retval Status
  */
static uint16_t NAND_Copy (NAND_ADDRESS Address_Src, NAND_ADDRESS Address_Dest, uint16_t PageToCopy)
{
  uint8_t Copybuff[512];
  for ( ; PageToCopy > 0 ; PageToCopy-- )
  {
    NAND_ReadSmallPage  ((uint8_t *)Copybuff, Address_Src , 1 );
    NAND_WriteSmallPage ((uint8_t *)Copybuff, Address_Dest, 1);
    NAND_AddressIncrement(&Address_Src);
    NAND_AddressIncrement(&Address_Dest);
  }

  return NAND_OK;
}

/**
  * @brief  Format the entire NAND flash
  * @param  None
  * @retval Status
  */
uint16_t NAND_Format(void)
{
  NAND_ADDRESS phAddress;
  uint32_t BlockIndex;

  for (BlockIndex = 0 ; BlockIndex < NAND_ZONE_SIZE * NAND_MAX_ZONE; BlockIndex++)
  {
    phAddress = NAND_ConvertPhyAddress(BlockIndex * NAND_BLOCK_SIZE );
    
    ReadSpareArea(BlockIndex * NAND_BLOCK_SIZE);
   
    /* Force the erase operation on all NAND Blocks including the bad Blocks and the erased Blocks */
    NAND_EraseBlock (phAddress);
  }
  /* Create a LUT table to be able to recognize the Bad Blocks */
  NAND_BuildLUT(0);
  
  return NAND_OK;
}

/**
  * @brief  NAND write clean up
  * @param  None
  * @retval Status
  */
static uint16_t NAND_Write_Cleanup(void)
{
  uint16_t  tempSpareArea [8];
  uint16_t  Page_Back;

  if ( Block_State == OLD_BLOCK )
  {
    /* precopy old first pages */
    if (Initial_Page != 0)
    {
      Page_Back = wAddress.Page;
      fAddress.Page = wAddress.Page = 0;
      NAND_Copy (wAddress, fAddress, Initial_Page);
      wAddress.Page =  Page_Back ;
    }

    /* postcopy remaining pages */
    if ((NAND_BLOCK_SIZE - (wAddress.Page + 1)) != 0)
    {
      NAND_AddressIncrement(&wAddress);
      fAddress.Page = wAddress.Page;
      NAND_Copy (wAddress, fAddress, NAND_BLOCK_SIZE - wAddress.Page);
    }

    /* assign logical address to new block */
    tempSpareArea [0] = LogAddress | USED_BLOCK ;
    tempSpareArea [1] = 0xFFFF;
    tempSpareArea [2] = 0xFFFF;

    fAddress.Page     = 0x00;
    NAND_WriteSpareArea( (uint8_t *)tempSpareArea , fAddress , 1);

    /* erase old block */
    NAND_EraseBlock(wAddress);
    NAND_CleanLUT(wAddress.Zone);
  }
  else
  {/* unused block case */
    /* assign logical address to the new used block */
    tempSpareArea [0] = LogAddress | USED_BLOCK ;
    tempSpareArea [1] = 0xFFFF;
    tempSpareArea [2] = 0xFFFF;

    wAddress.Page     = 0x00;
    NAND_WriteSpareArea((uint8_t *)tempSpareArea , wAddress, 1);
    NAND_CleanLUT(wAddress.Zone);
  }
  return NAND_OK;
}

/**
  * @brief  NAND Convert physical Address
  * @param  physical Address
  * @retval Status
  */
static NAND_ADDRESS NAND_ConvertPhyAddress(uint32_t Address)
{
  NAND_ADDRESS Address_t;

  Address_t.Page  = Address & (NAND_BLOCK_SIZE - 1);
  Address_t.Block = Address / NAND_BLOCK_SIZE;
  Address_t.Zone = 0;

  while (Address_t.Block >= MAX_PHY_BLOCKS_PER_ZONE)
  {
    Address_t.Block -= MAX_PHY_BLOCKS_PER_ZONE;
    Address_t.Zone++;
  }
  return Address_t;
}

/**
  * @brief  Build the look up table
  * @param  ZoneNbr
  * @retval Status
  * @note  THIS ALGORITHM IS A SUBJECT OF PATENT FOR STMICROELECTRONICS !!!!!
  */
static uint16_t NAND_BuildLUT(uint8_t ZoneNbr)
{

  uint16_t  pBadBlock, pCurrentBlock, pFreeBlock;
  SPARE_AREA  SpareArea;
  /*****************************************************************************
                                  1st step : Init.
  *****************************************************************************/
  /*Init the LUT (assume all blocks free) */
  for (pCurrentBlock = 0 ; pCurrentBlock < MAX_PHY_BLOCKS_PER_ZONE ; pCurrentBlock++)
  {
    LUT[pCurrentBlock] = FREE_BLOCK;  /* 12th bit is set to 1 */
  }

  /* Init Pointers */
  pBadBlock    = MAX_PHY_BLOCKS_PER_ZONE - 1;
  pCurrentBlock = 0;

  /*****************************************************************************
                         2nd step : locate used and bad blocks
  *****************************************************************************/

  while (pCurrentBlock < MAX_PHY_BLOCKS_PER_ZONE)
  {

    SpareArea = ReadSpareArea(pCurrentBlock * NAND_BLOCK_SIZE + (ZoneNbr * NAND_BLOCK_SIZE * MAX_PHY_BLOCKS_PER_ZONE));

    if ((SpareArea.DataStatus == 0) || (SpareArea.BlockStatus == 0))
    {

      LUT[pBadBlock--]    |= pCurrentBlock | (uint16_t)BAD_BLOCK ;
      LUT[pCurrentBlock] &= (uint16_t)~FREE_BLOCK;
      if (pBadBlock == MAX_LOG_BLOCKS_PER_ZONE)
      {
        return NAND_FAIL;
      }
    }
    else if (SpareArea.LogicalIndex != 0xFFFF)
    {

      LUT[SpareArea.LogicalIndex & 0x3FF] |= pCurrentBlock | VALID_BLOCK | USED_BLOCK;
      LUT[pCurrentBlock] &= (uint16_t)( ~FREE_BLOCK);
    }
    pCurrentBlock++ ;
  }

  /*****************************************************************************
     3rd step : locate Free Blocks by scanning the LUT already built partially
  *****************************************************************************/
  pFreeBlock = 0;
  for (pCurrentBlock = 0 ; pCurrentBlock < MAX_PHY_BLOCKS_PER_ZONE ; pCurrentBlock++ )
  {

    if ( !(LUT[pCurrentBlock]& USED_BLOCK))
    {
      do
      {
        if (LUT[pFreeBlock] & FREE_BLOCK)
        {

          LUT [pCurrentBlock] |= pFreeBlock;
          LUT [pFreeBlock]   &= ~FREE_BLOCK;
          break;
        }
        pFreeBlock++;
      }
      while ( pFreeBlock < MAX_PHY_BLOCKS_PER_ZONE );
    }
  }
  return NAND_OK;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
