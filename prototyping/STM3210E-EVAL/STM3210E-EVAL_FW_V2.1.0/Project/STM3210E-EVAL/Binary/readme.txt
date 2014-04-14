/**
  @page STM3210E_EVAL_Binary UM0549 STM3210E-EVAL Binary files Readme file
  
  @verbatim
  ******************** (C) COPYRIGHT 2013 STMicroelectronics *******************
  * @file    STM3210E-EVAL/Binary/readme.txt
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   Description of the UM0549 "STM3210E-EVAL demonstration firmware" 
  *          Binary files.
  ******************************************************************************
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
   @endverbatim

@par Description

This directory contains a set of STM3210E-EVAL Demo binary files that should be
programmed to the STM32F10x internal FLASH using different methods:
   - In-Circuit-Programming using the embedded bootloader
   - In-System Programming tool

 + Using "In-System Programming tool"
    - Connect the board through JTAG probe to your preferred in-system programming tool
    - Use "STM3210E-EVAL_Demo_V2.1.0.hex" file to reprogram the demonstration firmware 

    Note: You can use the embedded ST-LINK/V2 HW with STM32 ST-LINK Utility software,
          available for download from www.st.com, to program your board.

 + Using Bootloader
    - Configure the board to boot from "System Memory" (boot pin BOOT0:1 / option bit BOOT1:0)
    - Use "STM3210E-EVAL_Demo_V2.1.0.hex" file with the "STM32 Flash loader demonstrator"
      software, available for download from www.st.com, to program your board.
    - Once the binary is programmed, configure boot pins in "Boot from Flash" position
      and restart the board

      For more information about the STM32F10x Bootloader, please refer to "AN2606 
      STM32 microcontroller system memory boot mode."

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
