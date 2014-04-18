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
#include "main.h"
#include "stm32f10x_it.h"

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
show_led()
{

    uint32_t i = 0;
    for( i = 0; i < 0x0000FFFF; i++ )
    {}

    uint32_t which_led = GPIO_Pin_7; 

    GPIO_InitTypeDef  GPIO_InitStructure;

    RCC_APB2PeriphClockCmd( RCC_APB2Periph_GPIOF, ENABLE );

    GPIO_InitStructure.GPIO_Pin = which_led | GPIO_Pin_6;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
    GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_Init( GPIOF, &GPIO_InitStructure );

    GPIOF->BSRR = which_led;
}

/**
  * @brief  Main program.
  * @param  None
  * @retval None
  */
int main(void)
{
    /* Initialize the Demo */
    Demo_Init();

  while (1)
  {
    /* If SEL pushbutton is pressed */
    if(SELStatus == 1)
    {
      /* External Interrupt Disable */
      IntExtOnOffConfig(DISABLE);

      /* Execute Sel Function */
      SelFunc();

      /* External Interrupt Enable */
      IntExtOnOffConfig(ENABLE);
      /* Reset SELStatus value */
      SELStatus = 0;
    } 
  }
}

/**
  * @brief  Initializes the demonstration application.
  * @param  None
  * @retval None
  */
void Demo_Init(void)
{
  /* Enable GPIOA, GPIOB, GPIOC, GPIOD, GPIOE, GPIOF, GPIOG and AFIO clocks */
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOA | RCC_APB2Periph_GPIOB |RCC_APB2Periph_GPIOC 
         | RCC_APB2Periph_GPIOD | RCC_APB2Periph_GPIOE | RCC_APB2Periph_GPIOF | RCC_APB2Periph_GPIOG 
         | RCC_APB2Periph_AFIO, ENABLE);
  
  /* TIM1 Periph clock enable */
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_TIM1, ENABLE);

  RCC->CSR &= !RCC_CSR_RMVF;

  WWDG_DeInit();
 
  /*------------------- Resources Initialization -----------------------------*/
  /* GPIO Configuration */
  GPIO_Config();

  /* Interrupt Configuration */
  InterruptConfig();

  /* Configure the systick */    
  SysTick_Configuration();

  /*------------------- Drivers Initialization -------------------------------*/
  /* Initialize the LEDs toogling */
  LedShow_Init();

  /* Initialize the Low Power application */
  LowPower_Init();

  /* Initialize the LCD */
  STM3210E_LCD_Init();

  show_led();

  /* Clear the LCD */ 
  LCD_Clear(White);
  
  /* If HSE is not detected at program startup */
  if(HSEStartUpStatus == ERROR)
  {
    /* Generate NMI exception */
    SCB->ICSR |= SCB_ICSR_NMIPENDSET;
  }  
   
  /* Checks the availability of the bitmap files */
  CheckBitmapFilesStatus();

  /* Display the STM32 introduction */
  STM32Intro();

  /* Clear the LCD */ 
  LCD_Clear(White);

  /* Initialize the Calendar */
  Calendar_Init();

  /* Enable Leds toggling */
  LedShow(ENABLE);
  
  /* Initialize the Low Power application*/ 
  LowPower_Init();

  /* Set the LCD Back Color */
  LCD_SetBackColor(Blue);

  /* Set the LCD Text Color */
  LCD_SetTextColor(White);
  
  /* Initialize the Menu */
  Menu_Init();

  /* Display the main menu icons */
  ShowMenuIcons();
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
  * @brief  Inserts a delay time while no joystick RIGHT, LEFT and SEL 
  *         pushbuttons are pressed.
  * @param  nCount: specifies the delay time length (time base 10 ms).
  * @retval Pressed Key. This value can be: NOKEY, RIGHT, LEFT or SEL.
  */
uint32_t DelayJoyStick(__IO uint32_t nTime)
{
  __IO uint32_t keystate = 0;

  /* Enable the SysTick Counter */
  SysTick->CTRL |= SysTick_CTRL_ENABLE;

  TimingDelay = nTime;
 
  while((TimingDelay != 0) && (keystate != RIGHT) && (keystate != LEFT) && (keystate != SEL))
  {
    keystate = ReadKey();
  } 
  
  return keystate;
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

/**
  * @brief  Configure the leds pins as output pushpull: LED1, LED2, LED3 and LED4
  * @param  None
  * @retval None
  */
void LedShow_Init(void)
{
  TIM_TimeBaseInitTypeDef  TIM_TimeBaseStructure;
  TIM_OCInitTypeDef  TIM_OCInitStructure;

  TIM_TimeBaseStructInit(&TIM_TimeBaseStructure);
  TIM_OCStructInit(&TIM_OCInitStructure);

  /* Configure LEDs GPIO: as output push-pull */
  STM_EVAL_LEDInit(LED1);
  STM_EVAL_LEDInit(LED2);
  STM_EVAL_LEDInit(LED3);
  STM_EVAL_LEDInit(LED4);

  /* Time Base configuration */
  TIM_TimeBaseStructure.TIM_Prescaler = 719;
  TIM_TimeBaseStructure.TIM_CounterMode = TIM_CounterMode_Up;
  TIM_TimeBaseStructure.TIM_Period = 0x270F;
  TIM_TimeBaseStructure.TIM_ClockDivision = 0x0;
  TIM_TimeBaseStructure.TIM_RepetitionCounter = 0x0;

  TIM_TimeBaseInit(TIM1, &TIM_TimeBaseStructure);

  /* Channel 1 Configuration in Timing mode */
  TIM_OCInitStructure.TIM_OCMode = TIM_OCMode_Timing;
  TIM_OCInitStructure.TIM_OutputState = TIM_OutputState_Enable;
  TIM_OCInitStructure.TIM_OutputNState = TIM_OutputNState_Disable;
  TIM_OCInitStructure.TIM_Pulse = 0x0;
  
  TIM_OC1Init(TIM1, &TIM_OCInitStructure); 
}

/**
  * @brief  Enables or disables LED1, LED2, LED3 and LED4 toggling.
  * @param  None
  * @retval None
  */
void LedShow(FunctionalState NewState)
{
  /* Enable LEDs toggling */
  if(NewState == ENABLE)
  {
    LedShowStatus = 1;
    /* Enable the TIM1 Update Interrupt */
    TIM_ITConfig(TIM1, TIM_IT_Update, ENABLE);
    /* TIM1 counter enable */
    TIM_Cmd(TIM1, ENABLE);
  }
  /* Disable LEDs toggling */
  else
  {
    LedShowStatus = 0;
    /* Disable the TIM1 Update Interrupt */
    TIM_ITConfig(TIM1, TIM_IT_Update, DISABLE);
    /* TIM1 counter disable */
    TIM_Cmd(TIM1, DISABLE);
  }
}

/**
  * @brief  Get the LedShowStatus value.
  * @param  None
  * @retval LedShowStatus Value
  */
uint32_t Get_LedShowStatus(void)
{
  return LedShowStatus;
}

/**
  * @brief  Checks the bitmap files availability and display a warning message 
  * if these files doesn't exit.
  * @param  None
  * @param  None
  * @retval None
  */
void CheckBitmapFilesStatus(void)
{
  /* Checks if the Bitmap files are loaded */
  if(CheckBitmapFiles() != 0)
  {
    /* Set the LCD Back Color */
    LCD_SetBackColor(Blue);

    /* Set the LCD Text Color */
    LCD_SetTextColor(White);    
    LCD_DisplayStringLine(Line0, "      Warning       ");
    LCD_DisplayStringLine(Line1, "No loaded Bitmap    ");
    LCD_DisplayStringLine(Line2, "files. Demo can't be");
    LCD_DisplayStringLine(Line3, "executed.           ");
    LCD_DisplayStringLine(Line4, "Please be sure that ");
    LCD_DisplayStringLine(Line5, "all files are       ");
    LCD_DisplayStringLine(Line6, "correctly programmed");
    LCD_DisplayStringLine(Line7, "in the NOR FLASH and");
    LCD_DisplayStringLine(Line8, "restart the Demo.   ");
    LCD_DisplayStringLine(Line9, "                    ");
    
    /* Deinitializes the RCC */
    RCC_DeInit();
    
    /* Demo Can't Start */
    while(1)
    {
    }
  }
}

/**
  * @brief  Returns the HSE StartUp Status.
  * @param  None
  * @retval HSE StartUp Status
  */
ErrorStatus Get_HSEStartUpStatus(void)
{
  return (HSEStartUpStatus);
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t* file, uint32_t line)
{ 
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  
  LCD_Clear(White);
  LCD_DisplayStringLine(Line0, "   Assert Function  ");
  
  /* Infinite loop */
  while (1)
  {
  }
}
#endif

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
