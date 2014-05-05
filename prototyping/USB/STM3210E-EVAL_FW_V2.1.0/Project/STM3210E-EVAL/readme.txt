/**
  @page STM3210E_EVAL_Demo UM0549 "STM3210E-EVAL demonstration firmware" Readme file
  
  @verbatim
  ******************** (C) COPYRIGHT 2013 STMicroelectronics *******************
  * @file    STM3210E-EVAL/readme.txt 
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   Description of the UM0549 "STM3210E-EVAL demonstration firmware".
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

This directory contains a set of sources files and pre-configured projects that
describes the demonstration firmware running on the STM3210E-EVAL evaluation 
board, which can be used to evaluate the capabilities and on-board peripherals
of the STM32F10xx High-Density devices.


@par Directory contents 

 - "STM3210E-EVAL\inc": contains the STM3210E-EVAL firmware header files 

 - "STM3210E-EVAL\MDK-ARM": contains pre-configured project for MDK-ARM toolchain

 - "STM3210E-EVAL\EWARM": contains pre-configured project for EWARM toolchain

 - "STM3210E-EVAL\TASKING": contains pre-configured project for TASKING toolchain

 - "STM3210E-EVAL\RIDE": contains pre-configured project for RIDE toolchain

 - "STM3210E-EVAL\TrueSTUDIO": contains pre-configured project for TrueSTUDIO toolchain

 - "STM3210E-EVAL\src": contains the STM3210E-EVAL firmware source files


@par Hardware and Software environment 

  - This firmware runs on STM32F10xx High-Density devices.

  - This firmware has been tested with STMicroelectronics STM3210E-EVAL RevD 
    evaluation board.


@par How to use it ?

In order to load the demo code, you have do the following:
 - EWARM
    - Open the STM3210E-EVAL_Demo.eww workspace
    - Rebuild all files: Project->Rebuild all
    - Load project image: Project->Debug
    - Run program: Debug->Go(F5)

 - MDK-ARM 
    - Open the STM3210E-EVAL_Demo.Uv2 project
    - Rebuild all files: Project->Rebuild all target files
    - Load project image: Debug->Start/Stop Debug Session
    - Run program: Debug->Run (F5)

 - RIDE
    - Open the STM3210E-EVAL_Demo.rprj project
    - Load project image: Debug->start(ctrl+D)
    - Run program: Debug->Run(ctrl+F9) 

 - TASKING
      - Open TASKING toolchain.
      - Click on File->Switch Workspace->Other and browse to TASKING workspace directory.
      - Click on File->Import, select General->'Existing Projects into Workspace' and then click "Next". 
      - Browse to the TrueSTUDIO workspace directory, select the project:
         - STM3210E-EVAL
      - Rebuild all project files: Select the project in the "Project explorer" 
        window then click on Project->build project menu.
      - Run program: Run->Debug (F11)

 - TrueSTUDO:
      - Open the TrueSTUDIO toolchain.
      - Click on File->Switch Workspace->Other and browse to TrueSTUDIO workspace directory.
      - Click on File->Import, select General->'Existing Projects into Workspace' and then click "Next". 
      - Browse to the TrueSTUDIO workspace directory, select the project:
          - STM3210E-EVAL
      - Rebuild all project files: Select the project in the "Project explorer" 
        window then click on Project->build project menu.
      - Run program: Run->Debug (F11)
 
 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
