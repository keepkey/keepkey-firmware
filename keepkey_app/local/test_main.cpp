/**
  ******************************************************************************
  * @file    main.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   Main program body.
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
extern "C" {
#   include "main.h"
#   include "stm32f10x_it.h"
}

#include "KeepKeyDisplay.h"
#include "keepkey_oled_test_1.h"
#include "EvalKeepKeyBoard.h"


/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
static __IO uint32_t TimingDelay = 0;
static __IO uint32_t LedShowStatus = 0;
static __IO ErrorStatus HSEStartUpStatus = SUCCESS;
static __IO uint32_t SELStatus = 0;

/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

void
test_display(
        void
)
{
    EvalKeepKeyBoard* board = new EvalKeepKeyBoard();

    PixelBuffer* image = new PixelBuffer( 
            Pixel::A8,
            (uint32_t)image_data_keepkey_oled_test_1,
            64,
            256
    );

    PixelBuffer::transfer(
            image,
            board->display()->frame_buffer()
    );

    board->display()->frame_buffer()->taint();

    board->display()->refresh();
}


int 
main(
        void
)
{
    test_display();

    int i = 1;

    if( i == 0 )
        FSMC_NORSRAMInit( 0 );

    while( 1 )
    {}
}


#if 0
void
config_layout(
        void
)
{

    /// Define IDs for views and layouts.

    // IDs for layouts
    enum LayoutId
    {
        UNSET_LAYOUT_ID,
        TRANSACTION_LAYOUT,
        CONFIRMATION_LAYOUT,
        IDLE_LAYOUT
    };


    // IDs for views
    enum ViewId
    {
        UNSET_VIEW_ID,
        AMOUNT_TEXT,
        PROGRESS_BAR,
        IDLE_TEXT
    };



    /// Example layout and view configuration.

    // Create the layouts.
    Activity* transaction = new Activity( TRANSACTION_LAYOUT );
    Activity* confirmation = new Activity( CONFIRMATION_LAYOUT );
    Activity* idle = new Activity( IDLE_LAYOUT );

    LinearLayout* tx_base = new LinearLayout( 
            LinearLayout::VERTICAL,
            LayoutParams::MATCH_PARENT,
            LayoutParams::MATCH_PARENT 
    );

    // Create views
    TextView* amount = new TextView( AMOUNT_TEXT );
    ProgressBar* progress = new ProgressBar( PROGRESS_BAR );
    TextView* idle = new TextView( IDLE_TEXT );

    // Configure views
    LayoutParams* amount_layout = new LayoutParams( 
            LayoutParams::WRAP_CONTENT,
            LayoutParams::MATCH_PARENT 
    );
    amount_layout->set_padding( 10 );
    amount_layout->set_alignment( Style::ALIGN_CENTER, Style::ALIGN_TOP );
    amount_layout->set_height( Style::WRAP_CONTENT );
    amount_layout->set_width( Style::MATCH_PARENT );
    amount->set_layout_params( amount_layout );
    tx_base->add_view( amount );

    progress->set_width( Style::MATCH_PARENT );
    progress->set_height( 20 );
    progress->set_padding( 10, 10 );
    confirmation_layout->get_root_view()->add_child( progress );

    idle->set_padding( 0, 10 );
    idle->set_alignment( Style::ALIGN_CENTER, Style::ALIGN_CENTER );
    idle->set_height( Style::WRAP_CONTENT );
    idle->set_width( Style::MATCH_PARENT );
    idle_layout->get_root_view()->add_child( idle );


    /// Setting up the Window Manager

    // Create the display
    Display* display = new STM3210EDisplay( DISPLAY_BASE_ADDRESS );

    // Create the window manager instance and point it to the display.
    WindowManager* wm = new WindowManager( display );
    wm->add_layout( transaction_layout );
    wm->add_layout( confirmation_layout );
    wm->add_layout( idle_layout );
    wm->set_layout( IDLE_LAYOUT );


    /// Example of setting some text on an active view.

    // Write "Hello world!" on the idle text view.
    TextView* example = (TextView*)wm->get_view( IDLE_TEXT );
    example->set_text( "Hello world!" );

    // Redraw what is on the screen if anything has dirtied the
    // frame buffer.
    wm->redraw();
}
#endif


/**
  * @brief  Configures the used IRQ Channels and sets their priority.
  * @param  None
  * @retval None
  */
void InterruptConfig(void)
{ 
  NVIC_InitTypeDef NVIC_InitStructure;
  EXTI_InitTypeDef EXTI_InitStructure;
  
  /* Set the Vector Table base address at 0x08000000 */
  NVIC_SetVectorTable(NVIC_VectTab_FLASH, 0x00);
  
  /* Configure the Priority Group to 2 bits */
  NVIC_PriorityGroupConfig(NVIC_PriorityGroup_2);
  
  /* Enable the EXTI3 Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = EXTI3_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 2;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

  /* Enable the EXTI9_5 Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = EXTI9_5_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 2;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);
  
  /* Enable the EXTI15_10 Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = EXTI15_10_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 2;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);
  
  /* Enable the RTC Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = RTC_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);
 
  /* Enable the USB_LP_CAN_RX0 Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = USB_LP_CAN1_RX0_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);
  
  /* Enable the USB_HP_CAN_TX Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = USB_HP_CAN1_TX_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

  /* Enable the TIM1 UP Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = TIM1_UP_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 3;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

  /* Enable the RTC Alarm Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = RTCAlarm_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 1;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

  /* Enable the EXTI Line17 Interrupt */
  EXTI_InitStructure.EXTI_Mode = EXTI_Mode_Interrupt;
  EXTI_InitStructure.EXTI_Line = EXTI_Line17;
  EXTI_InitStructure.EXTI_Trigger = EXTI_Trigger_Rising;
  EXTI_InitStructure.EXTI_LineCmd = ENABLE;
  EXTI_Init(&EXTI_InitStructure);
}

/**
  * @brief  Configure a SysTick Base time to 10 ms.
  * @param  None
  * @retval None
  */
void SysTick_Configuration(void)
{
  /* Setup SysTick Timer for 10 msec interrupts  */
  if (SysTick_Config(SystemCoreClock / 100))
  { 
    /* Capture error */ 
    while (1);
  }
  
  /* Configure the SysTick handler priority */
  NVIC_SetPriority(SysTick_IRQn, 0x0);
}

/**
  * @brief  Enables or disables EXTI for the menu navigation keys :
  *         EXTI lines 3, 7 and 15 which correpond respectively
  *         to "DOWN", "SEL" and "UP".
  * @param  NewState: New state of the navigation keys. This parameter
  *                   can be: ENABLE or DISABLE.
  * @retval None
  */
void IntExtOnOffConfig(FunctionalState NewState)
{
  EXTI_InitTypeDef EXTI_InitStructure;

  /* Initializes the EXTI_InitStructure */
  EXTI_StructInit(&EXTI_InitStructure);

  /* Disable the EXTI line 3, 7 and 15 on falling edge */
  if(NewState == DISABLE)
  {
    EXTI_InitStructure.EXTI_Line = EXTI_Line3 | EXTI_Line7 | EXTI_Line15;
    EXTI_InitStructure.EXTI_LineCmd = DISABLE;
    EXTI_Init(&EXTI_InitStructure);
  }
  
  /* Enable the EXTI line 3, 7 and 15 on falling edge */
  else
  {
    /* Clear the the EXTI line 3, 7 and 15 interrupt pending bit */
    EXTI_ClearITPendingBit(EXTI_Line3 | EXTI_Line7 | EXTI_Line15);

    EXTI_InitStructure.EXTI_Mode = EXTI_Mode_Interrupt;
    EXTI_InitStructure.EXTI_Line = EXTI_Line3 | EXTI_Line7 | EXTI_Line15;
    EXTI_InitStructure.EXTI_Trigger = EXTI_Trigger_Falling;
    EXTI_InitStructure.EXTI_LineCmd = ENABLE;
    EXTI_Init(&EXTI_InitStructure);
  }
}

/**
  * @brief  Configures the different GPIO ports pins.
  * @param  None
  * @retval None
  */
void GPIO_Config(void)
{
  GPIO_InitTypeDef GPIO_InitStructure;

  /* Configure PG.07, PG.08, PG.13, PG.14 and PG.15 as input floating */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_7 | GPIO_Pin_8 | GPIO_Pin_13 | GPIO_Pin_14 | GPIO_Pin_15;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN_FLOATING;
  GPIO_Init(GPIOG, &GPIO_InitStructure);

  /* Configure PD.03 as input floating */
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_3;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN_FLOATING;
  GPIO_Init(GPIOD, &GPIO_InitStructure);

  /* RIGHT Button */
  GPIO_EXTILineConfig(GPIO_PortSourceGPIOG, GPIO_PinSource13);

  /* LEFT Button */
  GPIO_EXTILineConfig(GPIO_PortSourceGPIOG, GPIO_PinSource14);

  /* DOWN Button */
  GPIO_EXTILineConfig(GPIO_PortSourceGPIOD, GPIO_PinSource3);

  /* UP Button */
  GPIO_EXTILineConfig(GPIO_PortSourceGPIOG, GPIO_PinSource15);

  /* SEL Button */
  GPIO_EXTILineConfig(GPIO_PortSourceGPIOG, GPIO_PinSource7);

  /* KEY Button */
  GPIO_EXTILineConfig(GPIO_PortSourceGPIOG, GPIO_PinSource8);
}

/**
  * @brief  Inserts a delay time.
  * @param  nCount: specifies the delay time length (time base 10 ms).
  * @retval None
  */
void Delay(__IO uint32_t nCount)
{
  TimingDelay = nCount;

  /* Enable the SysTick Counter */
  SysTick->CTRL |= SysTick_CTRL_ENABLE;

  while(TimingDelay != 0);

  /* Disable the SysTick Counter */
  SysTick->CTRL &= ~SysTick_CTRL_ENABLE;

  /* Clear the SysTick Counter */
  SysTick->VAL = (uint32_t)0x0;
}

/**
  * @brief  Decrements the TimingDelay variable.
  * @param  None
  * @retval None
  */
void Decrement_TimingDelay(void)
{
  if (TimingDelay != 0x00)
  {
    TimingDelay--;
  }
}

/**
  * @brief  Sets the SELStatus variable.
  * @param  None
  * @retval None
  */
void Set_SELStatus(void)
{
  SELStatus = 1;
}
