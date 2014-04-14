/**
  ******************************************************************************
  * @file    menu.c
  * @author  MCD Application Team
  * @version V2.1.0
  * @date    02-August-2013
  * @brief   This file includes the menu navigation driver for the STM3210E-EVAL
  *          demonstration.
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
#include <stdio.h>
#include <string.h>

/* Private typedef -----------------------------------------------------------*/
typedef void (* tMenuFunc)(void);
typedef struct sMenuItem * tMenuItem;
typedef struct sMenu * tMenu;

/* Private define ------------------------------------------------------------*/
#define NumberOfIcons 10

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
uint8_t MenuItemIndex = 0, nMenuLevel = 0;
uint8_t ItemNumb[MAX_MENU_LEVELS];

tMenuItem psMenuItem, psCurrentMenuItem;
tMenu psPrevMenu[MAX_MENU_LEVELS];
tMenu psCurrentMenu;

struct sMenuItem
{
  uint8_t* pszTitle;
  tMenuFunc pfMenuFunc;
  tMenuFunc pfUpDownMenuFunc;
  tMenu psSubMenu;
};

struct sMenu
{
  uint8_t* pszTitle;
  tMenuItem psItems;
  uint8_t nItems;
};

NOR_IDTypeDef NOR_ID;

const uint32_t IconsAddr[] = {0x64FCAC7E, 0x64FCCCC0, 0x64FCED02, 0x64FD0D44, 0x64FD2D86,
                    0x64FD4DC8, 0x64FD6E0A, 0x64FD8E4C, 0x64FDAE8E, 0x64FDCED0,
                    0x64FDEF12};

const uint32_t SlideAddr[14] = {0x64D7285E, 0x64D980A0, 0x64DBD8E2, 0x64DE3124, 0x64E08966,
                      0x64E2E1A8, 0x64E539EA, 0x64E7922C, 0x64E9EA6E, 0x64EC42B0,
                      0x64EE9AF2, 0x64F0F334, 0x64F34B76, 0x64F5A3B8};
                      
                      

const uint32_t SlidesSpeech[14] = {0x00000000, 0x0006A166, 0x000D341C, 0x000F244E, 0x00150702,
                         0x00209D54, 0x0026B400, 0x002EB6AA, 0x00374BF0, 0x003B9778,
                         0x0043AF32, 0x00496000, 0x00521800, 0x0057AC40};

const uint32_t DelayTiming[14] = {2420, 2600, 800, 2400, 4725, 2100, 3300, 3500, 1600, 3300,
                        2420, 3400, 2275, 1670};

uint8_t SlidesCheck[6] = {0x42, 0x4D, 0x42, 0x58, 0x02, 0x00};
uint8_t Icons64Check[6] = {0x42, 0x4D, 0x42, 0x20, 0x00, 0x00};
uint8_t Icons128Check[6] = {0x42, 0x4D, 0x42, 0x80, 0x00, 0x00};


uint32_t STM32Banner[50] = {0x6461EB7A, 0x646443BC, 0x64669BFE, 0x6468F440, 0x646B4C82,
                       0x646DA4C4, 0x646FFD06, 0x64725548, 0x6474AD8A, 0x647705CC,
                       0x64795E0E, 0x647BB650, 0x647E0E92, 0x648066D4, 0x6482BF16,
                       0x64851758, 0x64876F9A, 0x6489C7DC, 0x648C201E, 0x648E7860,
                       0x6490D0A2, 0x649328E4, 0x64958126, 0x6497D968, 0x649A31AA,
                       0x649C89EC, 0x649EE22E, 0x64A13A70, 0x64A392B2, 0x64A5EAF4,
                       0x64A84336, 0x64AA9B78, 0x64ACF3BA, 0x64AF4BFC, 0x64B1A43E,
                       0x64B3FC80, 0x64B654C2, 0x64B8AD04, 0x64BB0546, 0x64BD5D88,
                       0x64BFB5CA, 0x64C20E0C, 0x64C4664E, 0x64C6BE90, 0x64C916D2,
                       0x64CB6F14, 0x64CDC756, 0x64D01F98, 0x64D277DA, 0x64D4D01C};

static __IO uint32_t CardInserted = 0;
static __IO uint32_t SmartCardStatus = 0;
extern SC_ATR SC_A2R;

static uint8_t TempCelsius_Display[] = "     +abc.def C     ";
static uint8_t TempFahrenheit_Display[] = "     +abc.def F     ";
static uint32_t Temp_Decimal = 0, TempCelsius_Value = 0, Temp_Value_Fahrenheit = 0;

/*------------------------------ Menu level 4 -------------------------------*/

/*------------------------------ Menu level 3 -------------------------------*/

struct sMenuItem STOPMenuItems[] = {{"    Exit: EXTI      ", EnterSTOPMode_EXTI, IdleFunc},
                                    {"  Exit: RTC Alarm   ", EnterSTOPMode_RTCAlarm, IdleFunc},
                                    {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu STOPMenu = {"     STOP Mode      ", STOPMenuItems, countof(STOPMenuItems)};

struct sMenuItem STANDBYMenuItems[] = {{"  Exit: Wakeup Pin  ", EnterSTANDBYMode_WAKEUP, IdleFunc},
                                       {"  Exit: RTC Alarm   ", EnterSTANDBYMode_RTCAlarm, IdleFunc},
                                       {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu STANDBYMenu = {"   STANDBY Mode     ", STANDBYMenuItems, countof(STANDBYMenuItems)};


struct sMenuItem SettingTimeMenuItems[] = { {"       Adjust       ", Time_Adjust, IdleFunc},
                                            {"        Show        ", Time_Show, IdleFunc},
                                            {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu TimeMenu = {"        Time        ", SettingTimeMenuItems, countof(SettingTimeMenuItems)};

struct sMenuItem SettingDateMenuItems[] = { {"       Adjust       ", Date_Adjust, IdleFunc},
                                            {"        Show        ", Date_Show, IdleFunc},
                                            {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu DateMenu = {"        Date        ", SettingDateMenuItems, countof(SettingDateMenuItems)};

struct sMenuItem SettingAlarmMenuItems[] = { {"       Adjust       ", Alarm_Adjust, IdleFunc},
                                             {"        Show        ", Alarm_Show, IdleFunc},
                                             {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu AlarmMenu = {"        Alarm       ", SettingAlarmMenuItems, countof(SettingAlarmMenuItems)};

/*------------------------------ Menu level 2 -------------------------------*/

struct sMenuItem AboutMenuItems[] = {{"       About        ", AboutFunc, IdleFunc},
                                     {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu AboutMenu = {"       About        ", AboutMenuItems, countof(AboutMenuItems)};

struct sMenuItem HelpMenuItems[] = {{"        Help        ", HelpFunc, IdleFunc},
                                    {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu HelpMenu = {"        Help        ", HelpMenuItems, countof(HelpMenuItems)};

struct sMenuItem TempSensorMenuItems[] = {{"    Temperature     ", Thermometer_Temperature, IdleFunc},
                                          {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu TempSensorMenu = {"    Thermometer     ", TempSensorMenuItems, countof(TempSensorMenuItems)};


struct sMenuItem SmartCardMenuItems[] = {{"     Smart Card     ", SmartCard_Start, IdleFunc},
                                         {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu SmartCardMenu = {"Smart Card Interface", SmartCardMenuItems, countof(SmartCardMenuItems)};


struct sMenuItem LowPowerMenuItems[] = {{"        STOP        ", IdleFunc, IdleFunc, &STOPMenu},
                                        {"       STANDBY      ", IdleFunc, IdleFunc, &STANDBYMenu},
                                        {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu LowPowerMenu = {"    Low Power Mode  ", LowPowerMenuItems, countof(LowPowerMenuItems)};


struct sMenuItem WavePlayerMenuItems[] = {{"    Wave Player     ", WavePlayer_StartSpeaker, IdleFunc},
                                          {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu WavePlayerMenu = {"    Wave Player     ", WavePlayerMenuItems, countof(WavePlayerMenuItems)};

struct sMenuItem AnimMenuItems[] = {{"    STM32 Banner    ", STM32BannerFunc, IdleFunc},
                                    {" STM32 Display Speed", STM32BannerSpeedFunc, IdleFunc},
                                    {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu AnimMenu = {"      Animation     ", AnimMenuItems, countof(AnimMenuItems)};

struct sMenuItem USBMassMenuItems[] = {{"       Start        ", Mass_Storage_Start, IdleFunc},
                                       {"NAND Physical Format", Mass_Storage_Recovery, IdleFunc},
                                       {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu USBMassMenu = {"  USB Mass Storage  ", USBMassMenuItems, countof(USBMassMenuItems)};


struct sMenuItem CalendarMenuItems[] = {{"        Time        ", IdleFunc, IdleFunc, &TimeMenu},
                                        {"        Date        ", IdleFunc, IdleFunc, &DateMenu},
                                        {"        Alarm       ", IdleFunc, IdleFunc, &AlarmMenu},
                                        {"        Return      ", ReturnFunc, IdleFunc}};
struct sMenu CalendarMenu = {"       Calendar     ", CalendarMenuItems, countof(CalendarMenuItems)};

struct sMenuItem ProdPresMenuItems[] = {{"       Start        ", ProductPres, IdleFunc},
                                        {"       Return       ", ReturnFunc, IdleFunc}};
struct sMenu ProdPresMenu = {"Product Presentation", ProdPresMenuItems, countof(ProdPresMenuItems)};

/*------------------------------ Menu level 1 -------------------------------*/
struct sMenuItem MainMenuItems[] = {
  {"Product Presentation", IdleFunc, IdleFunc, &ProdPresMenu},
  {"       Calendar     ", IdleFunc, IdleFunc, &CalendarMenu},
  {"      Animation     ", IdleFunc, IdleFunc, &AnimMenu},
  {"    Wave Player     ", IdleFunc, IdleFunc, &WavePlayerMenu},
  {"  USB Mass Storage  ", IdleFunc, IdleFunc, &USBMassMenu},
  {"  Low Power Modes   ", IdleFunc, IdleFunc, &LowPowerMenu},
  {"Smart Card Interface", IdleFunc, IdleFunc, &SmartCardMenu},
  {"    Thermometer     ", IdleFunc, IdleFunc, &TempSensorMenu},
  {"         Help       ", IdleFunc, IdleFunc, &HelpMenu},
  {"        About       ", IdleFunc, IdleFunc, &AboutMenu}};
struct sMenu MainMenu = {"     Main menu      ", MainMenuItems, countof(MainMenuItems)};

/* Private function prototypes -----------------------------------------------*/
static uint8_t Buffercmp(uint8_t* pBuffer1, uint8_t* pBuffer2, uint16_t BufferLength);
static void ADC_Config(void);
static uint8_t HexToAsciiLow(uint8_t byte);
static uint8_t HexToAsciiHigh(uint8_t byte);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Initializes the navigation menu.
  * @param  None
  * @retval None
  */
void Menu_Init(void)
{
  psCurrentMenu = &MainMenu;
  psPrevMenu[nMenuLevel] = psCurrentMenu;
  psMenuItem = MainMenuItems;
}

/**
  * @brief  Displays the current menu.
  * @param  None
  * @retval None
  */
void DisplayMenu(void)
{
  uint32_t Line = 0, index = 0;
  tMenuItem psMenuItem2;

  /* Set the Back Color */
  LCD_SetBackColor(Blue);
  /* Set the Text Color */
  LCD_SetTextColor(White);

  /* Clear the LCD Screen */
  LCD_Clear(White);

  LCD_DisplayStringLine(Line, psCurrentMenu->pszTitle);
  Line += 24;

  /* Set the Back Color */
  LCD_SetBackColor(White);

  /* Set the Text Color */
  LCD_SetTextColor(Blue);

  while(!(index >= (psCurrentMenu->nItems)))
  {
    psMenuItem2 = &(psCurrentMenu->psItems[index]);
    LCD_DisplayStringLine(Line, psMenuItem2->pszTitle);
    index++;
    Line += 24;
  }
  /* Set the Back Color */
  LCD_SetBackColor(Green);

  /* Set the Text Color */
  LCD_SetTextColor(White);

  /* Get the current menu */
  psMenuItem = &(psCurrentMenu->psItems[MenuItemIndex]);

  LCD_DisplayStringLine(((MenuItemIndex + 1) * 24), psMenuItem->pszTitle);
}

/**
  * @brief  This function is executed when "SEL" push-buttton is pressed.
  * @param  None
  * @retval None
  */
void SelFunc(void)
{
  psCurrentMenuItem = psMenuItem;

  if(psMenuItem->psSubMenu != '\0')
  {
    /* Update the current Item by the submenu */
    MenuItemIndex = 0;
    psCurrentMenu = psMenuItem->psSubMenu;
    psMenuItem = &(psCurrentMenu->psItems)[MenuItemIndex];
    DisplayMenu();
    nMenuLevel++;
    psPrevMenu[nMenuLevel] = psCurrentMenu;
  } 
  psCurrentMenuItem->pfMenuFunc();
}

/**
  * @brief  This function is executed when any of "UP" push-butttons is pressed.
  * @param  None
  * @retval None
  */
void UpFunc(void)
{
  /* Set the Back Color */
  LCD_SetBackColor(White);
  /* Set the Text Color */
  LCD_SetTextColor(Blue);
  psMenuItem = &psCurrentMenu->psItems[MenuItemIndex];
  LCD_DisplayStringLine(((MenuItemIndex + 1) * 24), psMenuItem->pszTitle);

  if(MenuItemIndex > 0)
  {
    MenuItemIndex--;
  }
  else
  {
    MenuItemIndex = psCurrentMenu->nItems - 1;
  }
  /* Set the Back Color */
  LCD_SetBackColor(Green);
  /* Set the Text Color */
  LCD_SetTextColor(White);
  psMenuItem = &psCurrentMenu->psItems[MenuItemIndex];
  LCD_DisplayStringLine(((MenuItemIndex + 1) * 24), psMenuItem->pszTitle);
  ItemNumb[nMenuLevel] = MenuItemIndex;
}

/**
  * @brief  This function is executed when any of "Down" push-butttons is pressed.
  * @param  None
  * @retval None
  */
void DownFunc(void)
{
  /* Set the Back Color */
  LCD_SetBackColor(White);
  /* Set the Text Color */
  LCD_SetTextColor(Blue);
  psMenuItem = &psCurrentMenu->psItems[MenuItemIndex];
  LCD_DisplayStringLine(((MenuItemIndex + 1) * 24), psMenuItem->pszTitle);
      
  /* Test on the MenuItemIndex value before incrementing it */
  if(MenuItemIndex >= ((psCurrentMenu->nItems)-1))
  {
    MenuItemIndex = 0;
  }
  else
  {
    MenuItemIndex++;
  }
  /* Set the Back Color */
  LCD_SetBackColor(Green);
  /* Set the Text Color */
  LCD_SetTextColor(White);
  /* Get the current menu */
  psMenuItem = &(psCurrentMenu->psItems[MenuItemIndex]);
  LCD_DisplayStringLine(((MenuItemIndex + 1) * 24), psMenuItem->pszTitle);
  ItemNumb[nMenuLevel] = MenuItemIndex;
}

/**
  * @brief  This function is executed when the "RETURN" menu is selected.
  * @param  None
  * @retval None
  */
void ReturnFunc(void)
{
  psMenuItem->pfUpDownMenuFunc();

  if(nMenuLevel == 0)
  {
    nMenuLevel++;
  }

  psCurrentMenu = psPrevMenu[nMenuLevel-1];
  psMenuItem = &psCurrentMenu->psItems[0];
  ItemNumb[nMenuLevel] = 0;
  MenuItemIndex = 0;
  nMenuLevel--;

  if(nMenuLevel != 0)
  {
    DisplayMenu();
  }
  else
  {
    ShowMenuIcons();
  }
}

/**
  * @brief  Reads key from demoboard.
  * @param  None
  * @retval RIGHT, LEFT, SEL, UP, DOWN or NOKEY
  */
uint8_t ReadKey(void)
{
  /* "right" key is pressed */
  if (!STM_EVAL_PBGetState(BUTTON_RIGHT))
  {
    while (STM_EVAL_PBGetState(BUTTON_RIGHT) == Bit_RESET);
    return RIGHT;
  }
  /* "left" key is pressed */
  if (!STM_EVAL_PBGetState(BUTTON_LEFT))
  {
    while (STM_EVAL_PBGetState(BUTTON_LEFT) == Bit_RESET);
    return LEFT;
  }
  /* "up" key is pressed */
  if (!STM_EVAL_PBGetState(BUTTON_UP))
  {
    while (STM_EVAL_PBGetState(BUTTON_UP) == Bit_RESET);
    return UP;
  }
  /* "down" key is pressed */
  if (!STM_EVAL_PBGetState(BUTTON_DOWN))
  {
    while (STM_EVAL_PBGetState(BUTTON_DOWN) == Bit_RESET);
    return DOWN;
  }
  /* "sel" key is pressed */
  if (!STM_EVAL_PBGetState(BUTTON_SEL))
  {
    while (STM_EVAL_PBGetState(BUTTON_SEL) == Bit_RESET);
    return SEL;
  }
  /* "KEY" key is pressed */
  if (!STM_EVAL_PBGetState(BUTTON_KEY))
  {
    while (STM_EVAL_PBGetState(BUTTON_KEY) == Bit_RESET);
    return KEY;
  }
  /* No key is pressed */
  else
  {
    return NOKEY;
  }
}

/**
  * @brief  Idle function.
  * @param  None
  * @retval None
  */
void IdleFunc(void)
{
  /* Nothing to execute: return */
  return;
}

/**
  * @brief  Display menu icons.
  * @param  None
  * @retval None
  */
void DisplayIcons(void)
{
  uint32_t i = 0, j = 0, l = 0,  iconline = 0, iconcolumn = 0;
  
  iconline = 98;
  iconcolumn = 290 ;
    
  for(i = 0; i < 3; i++)
  {
    for(j = 0; j < 4; j++)
    {
      RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE); 
      LCD_SetDisplayWindow(iconline, iconcolumn, 64, 64);
      RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE); 
      LCD_NORDisplay(IconsAddr[l]);
      iconcolumn -= 65;
      l++;
      if(l == NumberOfIcons)
      {
        return;
      }
    }
    iconline += 65;
    iconcolumn = 290;
  }
}

/**
  * @brief  Show the main menu icon.
  * @param  None
  * @retval None
  */
void ShowMenuIcons(void)
{
  uint32_t MyKey = 0, i = 0;  
  uint16_t IconRect[12][2] ={{34, 290}, {34, 225}, {34, 160}, {34, 95},
                       {99, 290}, {99, 225}, {99, 160}, {99, 95},
                       {164, 290}, {164, 225}, {164, 160}, {164, 95}};

  /* Disable the JoyStick interrupts */
  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }

  /* Initializes the Menu state machine */
  Menu_Init();

  MenuItemIndex = 0;
  
  /* Clear*/
  LCD_Clear(White);

  /* Set the Back Color */
  LCD_SetBackColor(Blue);

  /* Set the Text Color */
  LCD_SetTextColor(White);

  LCD_DisplayStringLine(Line0, psMenuItem->pszTitle);
  
  /* Set the Back Color */
  LCD_SetBackColor(White);

  /* Set the Text Color */
  LCD_SetTextColor(Blue);

  /* Displays Icons */    
  DisplayIcons();

  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  /* Disable LCD Window mode */
  LCD_WindowModeDisable(); 


  LCD_DrawRect(IconRect[0][0], IconRect[0][1], 64, 65);

  while(GPIO_ReadInputDataBit(GPIOG, GPIO_Pin_13) == RESET)
  {
  }
  /* Endless loop */
  while(1)
  {
    /* Check which key is pressed */
    MyKey = ReadKey();

    /* If "UP" pushbutton is pressed */
    if(MyKey == UP)
    {
      /* Set the Text Color */
      LCD_SetTextColor(White);

      LCD_DrawRect(IconRect[i][0], IconRect[i][1], 64, 65);

      if(i <= 3)
      {
        i += 8;
        if(i >= NumberOfIcons)
        {
          i = (NumberOfIcons - 1);
        }
      }
      else
      {
        i -= 4;
      }
      /* Set the Text Color */
      LCD_SetTextColor(Blue);
      LCD_DrawRect(IconRect[i][0], IconRect[i][1], 64, 65);

      /* Set the Back Color */
      LCD_SetBackColor(Blue);
      /* Set the Text Color */
      LCD_SetTextColor(White);
      /* Test on the MenuItemIndex value before incrementing it */
      if(MenuItemIndex <= 3)
      {
        MenuItemIndex += 8;
        if(MenuItemIndex >= NumberOfIcons)
        {
          MenuItemIndex = (NumberOfIcons - 1);
        }
      }
      else
      {
        MenuItemIndex -= 4;
      }
      /* Get the current menu */
      psMenuItem = &(psCurrentMenu->psItems[MenuItemIndex]);
      LCD_DisplayStringLine(Line0, psMenuItem->pszTitle);
      ItemNumb[nMenuLevel] = MenuItemIndex;
    }
    /* If "DOWN" pushbutton is pressed */
    if(MyKey == DOWN)
    {
      /* Set the Text Color */
      LCD_SetTextColor(White);
      LCD_DrawRect(IconRect[i][0], IconRect[i][1], 64, 65);
      if(i >= 8)
      {
        i -= 8;
      }
      else
      {
        i += 4;
        if(i >= NumberOfIcons)
        {
          i = (NumberOfIcons - 1);
        }
      }
      /* Set the Text Color */
      LCD_SetTextColor(Blue);
      LCD_DrawRect(IconRect[i][0], IconRect[i][1], 64, 65);

      /* Set the Back Color */
      LCD_SetBackColor(Blue);
      /* Set the Text Color */
      LCD_SetTextColor(White);
      /* Test on the MenuItemIndex value before incrementing it */
      if(MenuItemIndex >= 8)
      {
        MenuItemIndex -= 8;
      }
      else
      {
        MenuItemIndex += 4;
        if(MenuItemIndex >= NumberOfIcons)
        {
          MenuItemIndex = (NumberOfIcons - 1);
        }
      }
      /* Get the current menu */
      psMenuItem = &(psCurrentMenu->psItems[MenuItemIndex]);
      LCD_DisplayStringLine(Line0, psMenuItem->pszTitle);
      ItemNumb[nMenuLevel] = MenuItemIndex;
    }
    /* If "LEFT" pushbutton is pressed */
    if(MyKey == LEFT)
    {
      /* Set the Text Color */
      LCD_SetTextColor(White);
      LCD_DrawRect(IconRect[i][0], IconRect[i][1], 64, 65);
      if(i == 0)
      {
        i = (NumberOfIcons - 1);
      }
      else
      {
        i--;
      }
      /* Set the Text Color */
      LCD_SetTextColor(Blue);
      LCD_DrawRect(IconRect[i][0], IconRect[i][1], 64, 65);

      /* Set the Back Color */
      LCD_SetBackColor(Blue);
      /* Set the Text Color */
      LCD_SetTextColor(White);
      if(MenuItemIndex > 0)
      {
        MenuItemIndex--;
      }
      else
      {
        MenuItemIndex = psCurrentMenu->nItems - 1;
      }

      psMenuItem = &psCurrentMenu->psItems[MenuItemIndex];
      LCD_DisplayStringLine(Line0, psMenuItem->pszTitle);
      ItemNumb[nMenuLevel] = MenuItemIndex;
    }
    /* If "RIGHT" pushbutton is pressed */
    if(MyKey == RIGHT)
    {
      /* Set the Text Color */
      LCD_SetTextColor(White);
      LCD_DrawRect(IconRect[i][0], IconRect[i][1], 64, 65);
      if(i == (NumberOfIcons - 1))
      {
        i = 0x00;
      }
      else
      {
        i++;
      }
      /* Set the Text Color */
      LCD_SetTextColor(Blue);
      LCD_DrawRect(IconRect[i][0], IconRect[i][1], 64, 65);

      /* Set the Back Color */
      LCD_SetBackColor(Blue);
      /* Set the Text Color */
      LCD_SetTextColor(White);
      /* Test on the MenuItemIndex value before incrementing it */
      if(MenuItemIndex >= ((psCurrentMenu->nItems) - 1))
      {
        MenuItemIndex = 0;
      }
      else
      {
        MenuItemIndex++;
      }
      /* Get the current menu */
      psMenuItem = &(psCurrentMenu->psItems[MenuItemIndex]);
      LCD_DisplayStringLine(Line0, psMenuItem->pszTitle);
      ItemNumb[nMenuLevel] = MenuItemIndex;
    }
    /* If "SEL" pushbutton is pressed */
    if(MyKey == SEL)
    {
      SelFunc();
      IntExtOnOffConfig(ENABLE);
      return;
    }
  }    
}

/**
  * @brief  Display the STM32 introduction.
  * @param  None
  * @retval None
  */
void STM32Intro(void)
{
  uint32_t GPIOD_CRL = GPIOD->CRL,  GPIOD_CRH = GPIOD->CRH;
  uint32_t GPIOE_CRL = GPIOE->CRL,  GPIOE_CRH = GPIOE->CRH;
  uint32_t GPIOF_CRL = GPIOF->CRL,  GPIOF_CRH = GPIOF->CRH;
  uint32_t GPIOG_CRL = GPIOG->CRL,  GPIOG_CRH = GPIOG->CRH;
  
  /* Set the Back Color */
  LCD_SetBackColor(White);
  /* Set the Text Color */
  LCD_SetTextColor(Blue);
  
  LCD_SetDisplayWindow(239, 0x13F, 240, 320);
  LCD_NORDisplay(ST_LOGO);
  Delay(100);
  
  LCD_SetDisplayWindow(239, 0x13F, 240, 320);
  LCD_NORDisplay(SlideAddr[0]);  
  Delay(100); 

  GPIOD->CRL = GPIOD_CRL;
  GPIOD->CRH = GPIOD_CRH;
  GPIOE->CRL = GPIOE_CRL;
  GPIOE->CRH = GPIOE_CRH;
  GPIOF->CRL = GPIOF_CRL;
  GPIOF->CRH = GPIOF_CRH;
  GPIOG->CRL = GPIOG_CRL;
  GPIOG->CRH = GPIOG_CRH;
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE); 
}

/**
  * @brief  Display the Help menu.
  * @param  None
  * @retval None
  */
void HelpFunc(void)
{ 
  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }

  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  LCD_SetDisplayWindow(239, 0x13F, 240, 320);
  LCD_NORDisplay(HELP);
  
  while(ReadKey() != NOKEY)
  {
  }
  while(ReadKey() == NOKEY)
  {
  }
  
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  /* Set the Back Color */
  LCD_SetBackColor(Blue);
  /* Set the Text Color */
  LCD_SetTextColor(White);

  LCD_DisplayStringLine(Line0, "UP, DOWN, RIGHT and ");
  LCD_DisplayStringLine(Line1, "LEFT push-buttons   ");
  LCD_DisplayStringLine(Line2, "perform circular    ");
  LCD_DisplayStringLine(Line3, "navigation in the   ");
  LCD_DisplayStringLine(Line4, "main menu, current  ");
  LCD_DisplayStringLine(Line5, "menu items. SEL     ");
  LCD_DisplayStringLine(Line6, "push-button selects ");
  LCD_DisplayStringLine(Line7, "the current item. UP");
  LCD_DisplayStringLine(Line8, "and DOWN perform    ");
  LCD_DisplayStringLine(Line9, "vertical navigation.");
  
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);
  while(ReadKey() == NOKEY)
  {
  }
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  LCD_Clear(White);
  DisplayMenu();
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Display the About menu.
  * @param  None
  * @retval None
  */
void AboutFunc(void)
{
  LCD_Clear(White);

  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  } 
  /* Set the Back Color */
  LCD_SetBackColor(Blue);
  /* Set the Text Color */
  LCD_SetTextColor(White);

  LCD_ClearLine(Line0);
  LCD_DisplayStringLine(Line1, "   STM3210E-EVAL    ");
  LCD_DisplayStringLine(Line2, "   Demonstration    ");
  LCD_DisplayStringLine(Line3, "   Version 2.1.0    ");
  LCD_ClearLine(Line4);
  LCD_DisplayStringLine(Line5, "MCD Application Team");
  LCD_DisplayStringLine(Line6, "   COPYRIGHT 2013   ");
  LCD_DisplayStringLine(Line7, " STMicroelectronics ");
  LCD_ClearLine(Line8);
  LCD_DisplayStringLine(Line9, "  www.st.com/stm32  ");

  while(ReadKey() == NOKEY)
  {
  }

  LCD_Clear(White);
  DisplayMenu();
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Display a picture from the NOR Flash.
  * @param  None
  * @retval None
  */
void LCD_NORDisplay(uint32_t address)
{
  uint32_t GPIOD_CRL = GPIOD->CRL,  GPIOD_CRH = GPIOD->CRH;
  uint32_t GPIOE_CRL = GPIOE->CRL,  GPIOE_CRH = GPIOE->CRH;
  uint32_t GPIOF_CRL = GPIOF->CRL,  GPIOF_CRH = GPIOF->CRH;
  uint32_t GPIOG_CRL = GPIOG->CRL,  GPIOG_CRH = GPIOG->CRH;

  /* Write/read to/from FSMC SRAM memory  *************************************/
  /* Enable the FSMC Clock */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  
  /* Configure FSMC Bank1 NOR/SRAM2 */
  NOR_Init();
  
  /* Read NOR memory ID */
  NOR_ReadID(&NOR_ID);

  NOR_ReturnToReadMode();

  /* Slide nÝ: index */
  LCD_WriteBMP(address);

  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);
 
  GPIOD->CRL = GPIOD_CRL;
  GPIOD->CRH = GPIOD_CRH;
  GPIOE->CRL = GPIOE_CRL;
  GPIOE->CRH = GPIOE_CRH;
  GPIOF->CRL = GPIOF_CRL;
  GPIOF->CRH = GPIOF_CRH;
  GPIOG->CRL = GPIOG_CRL;
  GPIOG->CRH = GPIOG_CRH;
}

/**
  * @brief  Displays the temperature in Celsius and fahrenheit degree.
  * @param  None
  * @retval None
  */
void Thermometer_Temperature(void)
{
  uint32_t i = 0, pressedkey = 0;
  
  while(ReadKey() != NOKEY)
  {
  }
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);
  
  /* Initialize the Temperature Sensor */
  LM75_Init();
  
  if(LM75_GetStatus() == SUCCESS)
  {
    /* Disable the JoyStick Interrupts */
    IntExtOnOffConfig(DISABLE);

    RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
    /* Clear the LCD */
    LCD_Clear(White);
  
    /* Set the Icon display window */ 
    LCD_SetDisplayWindow(150, 190, 64, 64);
 
    /* Display the Thermometer icon */
    LCD_NORDisplay(TSENSOR);

    RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
    /* Disable LCD Window mode */
    LCD_WindowModeDisable();

    /* Set the Back Color */
    LCD_SetBackColor(Red);
    /* Set the Text Color */
    LCD_SetTextColor(White);

    LCD_DisplayStringLine(Line2, "     Temperature    ");

    /* Set the Back Color */
    LCD_SetBackColor(Blue);
    /* Set the Text Color */
    LCD_SetTextColor(Green);

    RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);

    /* Wait until no key is pressed */
    while(ReadKey() != NOKEY)
    {
    }
    
    /* Wait until a key is beiing pressed */
    while(pressedkey == NOKEY)
    {
      /* Initialize the Temperature Sensor */
      LM75_Init();

      /* Get double of Temperature value */
      TempCelsius_Value = LM75_ReadTemp() << 2;

	  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

      if(TempCelsius_Value <= 1023)
      {
        /* Positive temperature measured */
        TempCelsius_Display[5] = '+';
        TempFahrenheit_Display[5] = '+'; 
      }
      else
      {
        /* Negative temperature measured */
        TempCelsius_Display[5] = '-'; 
        TempFahrenheit_Display[5] = '-'; 
        /* Remove temperature value sign */
        TempCelsius_Value = 0x800 - TempCelsius_Value;
      }

      /* Calculate temperature digits in °C */
      Temp_Decimal = ((TempCelsius_Value & 7) * 1000 / 8);
      TempCelsius_Display[10] = (Temp_Decimal / 100) + 0x30;
      TempCelsius_Display[11] = ((Temp_Decimal % 100) / 10) + 0x30;
      TempCelsius_Display[12] = ((Temp_Decimal % 100) % 10) + 0x30;
      TempCelsius_Value >>= 3;
      TempCelsius_Display[6] = (TempCelsius_Value / 100) + 0x30;
      TempCelsius_Display[7] = ((TempCelsius_Value % 100) / 10) + 0x30;
      TempCelsius_Display[8] = ((TempCelsius_Value % 100) % 10) + 0x30;

      /* Convert temperature °C to Fahrenheit */
      Temp_Value_Fahrenheit = ((9 * ((TempCelsius_Value * 1000) + Temp_Decimal)) / 5) + 32000;

      /* Calculate temperature digits in °F */
      TempFahrenheit_Display[6] = (Temp_Value_Fahrenheit / 100000) + 0x30;
      TempFahrenheit_Display[7] = ((Temp_Value_Fahrenheit % 100000) /10000) + 0x30;
      TempFahrenheit_Display[8] = ((Temp_Value_Fahrenheit % 100000) %10000/1000) + 0x30;
      TempFahrenheit_Display[10] = ((((Temp_Value_Fahrenheit % 100000) %10000) %1000) /100) + 0x30;
      TempFahrenheit_Display[11] = (((((Temp_Value_Fahrenheit % 100000) %10000) %1000) %100) /10) + 0x30;
      TempFahrenheit_Display[12] = (((((Temp_Value_Fahrenheit % 100000) %10000) %1000) %100) %10) + 0x30;

      /* Display Fahrenheit value on LCD */
      for(i = 0; i < 20; i++)
      {
        LCD_DisplayChar(Line7, (319 - (16 * i)), TempCelsius_Display[i]);
        LCD_DisplayChar(Line8, (319 - (16 * i)), TempFahrenheit_Display[i]);
      }
      RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, DISABLE);
      pressedkey = ReadKey(); 
    }
  }
  else
  {
    LCD_Clear(White);
    LCD_DisplayStringLine(Line2, " No TSENSOR Present ");
    LCD_DisplayStringLine(Line3, "Exit:  Push JoyStick");
    while(ReadKey() == NOKEY)
    {
    }
  }
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  LCD_Clear(White);
  /* Display menu */
  DisplayMenu();
  /* Enable the JoyStick interrupt */
  IntExtOnOffConfig(ENABLE);   
}

/**
  * @brief  Runs the Smart Card application.
  * @param  None
  * @retval None
  */
void SmartCard_Start(void)
{ 
  NVIC_InitTypeDef NVIC_InitStructure;
  EXTI_InitTypeDef EXTI_InitStructure;
  GPIO_InitTypeDef GPIO_InitStructure;
  /* APDU Transport Structures */
  SC_ADPU_Commands SC_ADPU;
  SC_ADPU_Responce SC_Responce;
  uint8_t TxBuffer[20], TxBuffer1[100], pressedkey = 0;
  uint32_t index = 0;

  SC_State SCState = SC_POWER_OFF;  

  LCD_Clear(White);

  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }

  for(index = 0; index < 100; index++)
  {
    TxBuffer1[index] = 0;
  }

  for(index = 0; index < 20; index++)
  {
    TxBuffer[index] = 0;
  }
  SPI2->I2SCFGR &= 0xF7FF;
  SPI2->CR1 &= 0xFFFB;
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_SPI2, DISABLE);

  /* Enable GPIO_LED, GPIO SC OFF and AFIO clocks */
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIO_LED | RCC_APB2Periph_OFF |
                         RCC_APB2Periph_AFIO, ENABLE);

  /* Configure Smartcard CMDVCC */
  GPIO_InitStructure.GPIO_Pin = SC_CMDVCC;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_Init(GPIO_CMDVCC, &GPIO_InitStructure);
  GPIO_SetBits(GPIO_CMDVCC, SC_CMDVCC);

  /* Configure Smartcard OFF  */
  GPIO_InitStructure.GPIO_Pin = SC_OFF;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN_FLOATING;
  GPIO_Init(GPIO_OFF, &GPIO_InitStructure);

  /* Configure Smartcard CMDVCC */
  GPIO_InitStructure.GPIO_Pin = SC_CMDVCC;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN_FLOATING;
  GPIO_Init(GPIO_CMDVCC, &GPIO_InitStructure);


  /* Clear the SC_EXTI_IRQ Pending Bit */
  NVIC_ClearPendingIRQ(SC_EXTI_IRQ);

  NVIC_InitStructure.NVIC_IRQChannel = SC_EXTI_IRQ;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
  NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
  NVIC_Init(&NVIC_InitStructure);

  /* Enable the USART3 Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = USART3_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 1;
  NVIC_Init(&NVIC_InitStructure);

  /* Smartcard OFF Pin */
  GPIO_EXTILineConfig(SC_PortSource, SC_PinSource);

  /* Clear SC EXTI Line Pending Bit */
  EXTI_ClearITPendingBit(SC_EXTI);
  
  EXTI_InitStructure.EXTI_Mode = EXTI_Mode_Interrupt;
  EXTI_InitStructure.EXTI_Trigger = EXTI_Trigger_Rising;
  EXTI_InitStructure.EXTI_Line = SC_EXTI;
  EXTI_InitStructure.EXTI_LineCmd = ENABLE;
  EXTI_Init(&EXTI_InitStructure);
  SmartCardStatus = 1;

  /* Set the LCD Back Color */
  LCD_SetBackColor(Blue);
  /* Set the LCD Text Color */
  LCD_SetTextColor(White);

  LCD_DisplayStringLine(Line1, " Please Insert Card ");
  LCD_DisplayStringLine(Line2, "Press SEL to exit.  ");

  pressedkey = ReadKey();

  /* Loop while no Smartcard is detected */  
  while((CardInserted == 0)&& (pressedkey != SEL))
  {
    pressedkey = ReadKey();
  }
  
  if(pressedkey == SEL)
  {
    LCD_ClearLine(Line2);
    LCD_DisplayStringLine(Line1, " Card non inserted  ");
    LCD_DisplayStringLine(Line4, "Push JoyStick to    ");
    LCD_DisplayStringLine(Line5, "exit.               ");

    while(ReadKey() == NOKEY)
    {
    }
    /* Deinitializes the USART3 */
    USART_DeInit(USART3);
    /* Disable USART3 clock */
    RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, DISABLE);

    /* Enable the USART3 Interrupt */
    NVIC_InitStructure.NVIC_IRQChannel = USART3_IRQn;
    NVIC_InitStructure.NVIC_IRQChannelCmd = DISABLE;
    NVIC_Init(&NVIC_InitStructure);

    /* SEL Button */
    GPIO_EXTILineConfig(GPIO_PortSourceGPIOG, GPIO_PinSource7);
  
    CardInserted = 0;
    SmartCardStatus = 0;

    SPI2->I2SCFGR |= 0x0800;
    RCC_APB1PeriphClockCmd(RCC_APB1Periph_SPI2, ENABLE);
    LCD_Clear(White);
    DisplayMenu();
    IntExtOnOffConfig(ENABLE);
    return;
  }
  LCD_DisplayStringLine(Line1, "   Card Inserted    ");
  LCD_DisplayStringLine(Line2, "   Decoding ATR...  ");
  
  /* Start SC Demo ---------------------------------------------------------*/
    
  /* Wait A2R --------------------------------------------------------------*/
  SCState = SC_POWER_ON;

  SC_ADPU.Header.CLA = 0x00;
  SC_ADPU.Header.INS = SC_GET_A2R;
  SC_ADPU.Header.P1 = 0x00;
  SC_ADPU.Header.P2 = 0x00;
  SC_ADPU.Body.LC = 0x00;
  index = 0xFF;
 
  while((SCState != SC_ACTIVE_ON_T0) && (index > 0))
  {
    SC_Handler(&SCState, &SC_ADPU, &SC_Responce);
    index--;
  }
  
  if(index == 0)
  {
    LCD_DisplayStringLine(Line1, "Non supported Card  ");
    LCD_DisplayStringLine(Line2, "Only ISO7816-3 T = 0");
    LCD_DisplayStringLine(Line3, "cards are supported.");
    LCD_DisplayStringLine(Line4, "Push JoyStick to    ");
    LCD_DisplayStringLine(Line5, "exit.               ");

    while(ReadKey() == NOKEY)
    {
    }
    /* Deinitializes the USART3 */
    USART_DeInit(USART3);
    /* Disable USART3 clock */
    RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, DISABLE);

    /* Enable the USART3 Interrupt */
    NVIC_InitStructure.NVIC_IRQChannel = USART3_IRQn;
    NVIC_InitStructure.NVIC_IRQChannelCmd = DISABLE;
    NVIC_Init(&NVIC_InitStructure);

    /* SEL Button */
    GPIO_EXTILineConfig(GPIO_PortSourceGPIOG, GPIO_PinSource7);
  
    CardInserted = 0;
    SmartCardStatus = 0;

    SPI2->I2SCFGR |= 0x0800;
    RCC_APB1PeriphClockCmd(RCC_APB1Periph_SPI2, ENABLE);
    LCD_Clear(White);
    DisplayMenu();
    IntExtOnOffConfig(ENABLE);
    return;
  }
  else
  {
    LCD_DisplayStringLine(Line1, "Smart card ISO7816-3");
    LCD_DisplayStringLine(Line2, "compatible.         ");
    LCD_DisplayStringLine(Line3, "Protocol T = 0      ");

    LCD_DisplayStringLine(Line5, "Push JoyStick to    ");
    LCD_DisplayStringLine(Line6, "continue.           ");

    while(ReadKey() == NOKEY)
    {
    }
  }

  LCD_Clear(White);
  /* Set the LCD Back Color */
  LCD_SetBackColor(Blue);
  /* Set the LCD Text Color */
  LCD_SetTextColor(White);

  LCD_DisplayStringLine(Line0, "    Decoded ATR     ");


  /* Set the LCD Back Color */
  LCD_SetBackColor(White);
  /* Set the LCD Text Color */
  LCD_SetTextColor(Red);

  LCD_ClearLine(Line2);

  sprintf((char*)TxBuffer,"TS = 0x%x, T0 = 0x%x", SC_A2R.TS, SC_A2R.T0); 
  LCD_DisplayStringLine(Line1, TxBuffer);

  sprintf((char*)TxBuffer,"Setup Characters :  "); 
  LCD_DisplayStringLine(Line2, TxBuffer);

  /* Set the LCD Back Color */
  LCD_SetBackColor(White);
  /* Set the LCD Text Color */
  LCD_SetTextColor(Blue);

  for(index = 0; index < (3 * SC_A2R.Tlength); index += 3)
  {
    TxBuffer1[index] = HexToAsciiHigh(SC_A2R.T[index/3]);
    TxBuffer1[index + 1] = HexToAsciiLow(SC_A2R.T[index/3]);
    TxBuffer1[index + 2] = ' ';   
  }

  LCD_DisplayStringLine(Line3, TxBuffer1);

  if(SC_A2R.Tlength > 7)
  {
    for(index = 21; index < (3 * SC_A2R.Tlength); index += 3)
    {
      TxBuffer1[index] = HexToAsciiHigh(SC_A2R.T[index/3]);
      TxBuffer1[index + 1] = HexToAsciiLow(SC_A2R.T[index/3]);
      TxBuffer1[index + 2] = ' ';   
    }
    LCD_DisplayStringLine(Line4, (TxBuffer1 + 21));
  }
  if(SC_A2R.Tlength > 14)
  {
    for(index = 42; index < (3 * SC_A2R.Tlength); index += 3)
    {
      TxBuffer1[index] = HexToAsciiHigh(SC_A2R.T[index/3]);
      TxBuffer1[index + 1] = HexToAsciiLow(SC_A2R.T[index/3]);
      TxBuffer1[index + 2] = ' ';   
    }
    LCD_DisplayStringLine(Line5, (TxBuffer1 + 42));
  }
  /* Set the LCD Back Color */
  LCD_SetBackColor(White);
  /* Set the LCD Text Color */
  LCD_SetTextColor(Red);

  sprintf((char*)TxBuffer,"Historical Characters"); 
  LCD_DisplayStringLine(Line6, TxBuffer);

  /* Set the LCD Back Color */
  LCD_SetBackColor(White);
  /* Set the LCD Text Color */
  LCD_SetTextColor(Blue);

  for(index = 0; index < (3 * SC_A2R.Hlength); index += 3)
  {
    TxBuffer1[index] = HexToAsciiHigh(SC_A2R.H[index/3]);
    TxBuffer1[index + 1] = HexToAsciiLow(SC_A2R.H[index/3]);
    TxBuffer1[index + 2] = ' ';   
  } 
  LCD_DisplayStringLine(Line7, TxBuffer1);

  if(SC_A2R.Hlength > 7)
  {
    for(index = 21; index < (3 * SC_A2R.Hlength); index += 3)
    {
      TxBuffer1[index] = HexToAsciiHigh(SC_A2R.H[index/3]);
      TxBuffer1[index + 1] = HexToAsciiLow(SC_A2R.H[index/3]);
      TxBuffer1[index + 2] = ' ';   
    }
    LCD_DisplayStringLine(Line8, (TxBuffer1 + 21));
  }
  if(SC_A2R.Hlength > 14)
  {
    for(index = 42; index < (3 * SC_A2R.Hlength); index += 3)
    {
      TxBuffer1[index] = HexToAsciiHigh(SC_A2R.H[index/3]);
      TxBuffer1[index + 1] = HexToAsciiLow(SC_A2R.H[index/3]);
      TxBuffer1[index + 2] = ' ';   
    }
    LCD_DisplayStringLine(Line9, (TxBuffer1 + 42));
  }

  while(ReadKey() == NOKEY)
  {
  }
  /* Deinitializes the USART3 */
  USART_DeInit(USART3);
  /* Disable USART3 clock */
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, DISABLE);

  /* Enable the USART3 Interrupt */
  NVIC_InitStructure.NVIC_IRQChannel = USART3_IRQn;
  NVIC_InitStructure.NVIC_IRQChannelCmd = DISABLE;
  NVIC_Init(&NVIC_InitStructure);

  /* SEL Button */
  GPIO_EXTILineConfig(GPIO_PortSourceGPIOG, GPIO_PinSource7);
  
  /* Configure Smartcard CMDVCC */
  GPIO_InitStructure.GPIO_Pin = SC_CMDVCC;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_Init(GPIO_CMDVCC, &GPIO_InitStructure);
  GPIO_SetBits(GPIO_CMDVCC, SC_CMDVCC);

  CardInserted = 0;
  SmartCardStatus = 0;

  SPI2->I2SCFGR |= 0x0800;
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_SPI2, ENABLE);
  LCD_Clear(White);
  DisplayMenu();
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Display the STM32 Banner Animation.
  * @param  None
  * @retval None
  */
void STM32BannerFunc(void)
{
  __IO uint32_t index = 0, KeyState = 0;

  IntExtOnOffConfig(DISABLE);
 
  while(ReadKey() != NOKEY)
  {
  }

  LCD_SetDisplayWindow(239, 0x13F, 240, 320);
  LCD_NORDisplay(STM32Banner[index++]);

 
  while(index < 50)
  {
    LCD_NORDisplay(STM32Banner[index++]); 
    Delay(6);

    if(index == 50)
    {
      index = 0;
    }
    KeyState = ReadKey();
    if (KeyState == SEL)
    {
      index = 50;
    }
  }	

  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  
  /* Set the Back Color */
  LCD_SetBackColor(Black);

  /* Set the Text Color */
  LCD_SetTextColor(White);

  LCD_Clear(White);
  LCD_DisplayStringLine(Line1, "Exit:  Push JoyStick");

  while(ReadKey() == NOKEY)
  {
  }

  LCD_Clear(White);
  DisplayMenu();
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Display the STM32 Banner Animation with a controlled speed.
  * @param  None
  * @retval None
  */
void STM32BannerSpeedFunc(void)
{
  __IO uint32_t index = 0, KeyState = 0;

  GPIO_InitTypeDef GPIO_InitStructure;  


  /* Configure PC.04 (ADC Channel14) as analog input -------------------------*/
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_4;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AIN;
  GPIO_Init(GPIOC, &GPIO_InitStructure);

  IntExtOnOffConfig(DISABLE);
 
  while(ReadKey() != NOKEY)
  {
  }

  /* Enable  ADC1 clock */
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_ADC1, ENABLE);
  
  /* Configure the ADC Channnel 14 */
  ADC_Config();

  /* Clear the LCD */
  LCD_Clear(White);
 

  LCD_SetTextColor(Red);
  LCD_DisplayStringLine(Line4, "Turn the Trimmer RV1");
  LCD_DisplayStringLine(Line5, "to control the delay");
  LCD_DisplayStringLine(Line6, "between two frames. ");
  LCD_DisplayStringLine(Line7, "Push JoyStick SEL to");
  LCD_DisplayStringLine(Line8, "start or stop.      ");

  while(ReadKey() != SEL)
  {
  }

  LCD_SetDisplayWindow(239, 0x13F, 240, 320);
  LCD_NORDisplay(SlideAddr[index++]);

 
  while(index < 14)
  {
    LCD_NORDisplay(SlideAddr[index++]); 
    Delay(ADC_GetConversionValue(ADC1)/10);

    if(index == 14)
    {
      index = 0;
    }
    KeyState = ReadKey();
    if (KeyState == SEL)
    {
      index = 14;
    }
  }	

  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  
  /* Set the Back Color */
  LCD_SetBackColor(Black);

  /* Set the Text Color */
  LCD_SetTextColor(White);

  LCD_Clear(White);
  LCD_DisplayStringLine(Line1, "Exit:  Push JoyStick");

  while(ReadKey() == NOKEY)
  {
  }

  LCD_Clear(White);
  DisplayMenu();
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Runs the Product Presentation menu.
  * @param  None
  * @retval None
  */
void ProductPres(void)
{
  __IO uint32_t index = 0, KeyState = 0, err = 0;

  IntExtOnOffConfig(DISABLE);

  while(ReadKey() != NOKEY)
  {
  }

  LCD_Clear(White);
  /* Set the Back Color */
  LCD_SetBackColor(Blue);
  /* Set the Text Color */
  LCD_SetTextColor(White);

  /* Initialize the audio file to determine the audio frequency 
    and the Data Length in order to set SysTick reload value */ 
  err = AudioFile_Init();

  /* Check if the initialization passed */
  if ((err == 1) || (err == 2))
  {
    LCD_DisplayError(err);

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

  /* Enable the FSMC that share a pin w/ I2C1 (LBAR) */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE); 

  LCD_ClearLine(Line0);
  LCD_DisplayStringLine(Line1, " Press SEL to start ");  
  LCD_ClearLine(Line2);
  LCD_ClearLine(Line3);
  LCD_DisplayStringLine(Line4, " When presentation  ");
  LCD_DisplayStringLine(Line5, "starts use RIGHT    "); 
  LCD_DisplayStringLine(Line6, "and LEFT to go to   ");
  LCD_DisplayStringLine(Line7, "the next/previous   ");
  LCD_DisplayStringLine(Line8, "slide and SEL to    ");
  LCD_DisplayStringLine(Line9, "exit.               ");

  while(ReadKey() != SEL)
  {
  }
  while(ReadKey() != NOKEY)
  {
  }

  SetVar_AudioDataIndex(SlidesSpeech[index]);
  I2S_CODEC_SpeakerHeadphoneSwap(OutputDevice_SPEAKER, AUDIO_FILE_ADDRESS); 
  
  while(index < 14)
  {  
    I2S_CODEC_Pause();
    /* Enable the FSMC Clock */
    RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  
    LCD_SetDisplayWindow(239, 0x13F, 240, 320);
    /* Slide nÝ: index */  
    LCD_NORDisplay(SlideAddr[index]);

    I2S_CODEC_Play(GetVar_AudioDataIndex()); 
    
    /* Clear the SysTick Counter */
    SysTick->VAL = (uint32_t)0x0;
    
    KeyState = DelayJoyStick(DelayTiming[index]);

    if(KeyState == LEFT)
    {
      if(index == 0)
      {
        index = 1;
      }
      index--;
      I2S_CODEC_Pause();
      SetVar_AudioDataIndex(SlidesSpeech[index]);
      I2S_CODEC_Play(GetVar_AudioDataIndex());
    }
    else if (KeyState == RIGHT)
    {
      if(index == 13)
      { 
        index = 15;
      }
      index++;
      I2S_CODEC_Pause();
      SetVar_AudioDataIndex(SlidesSpeech[index]);
      I2S_CODEC_Play(GetVar_AudioDataIndex());
    }
    else if (KeyState == SEL)
    {
      I2S_CODEC_Stop();
      index = 15;
    }
    else if (KeyState == NOKEY)
    {
      SetVar_AudioDataIndex(SlidesSpeech[++index]);
    }
  }

  /* Disable the SysTick Counter */
  SysTick->CTRL &= ~SysTick_CTRL_ENABLE;

  /* Clear the SysTick Counter */
  SysTick->VAL = (uint32_t)0x0;

  I2S_CODEC_Stop();

  /* Enable the FSMC Clock */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);

  LCD_Clear(Black);

  /* Set the Back Color */
  LCD_SetBackColor(Black);

  /* Set the Text Color */
  LCD_SetTextColor(White);

  LCD_DisplayStringLine(Line0, "  End of slide show ");
  LCD_DisplayStringLine(Line1, "Exit:  Push JoyStick");

  while(ReadKey() == NOKEY)
  {
  }

  LCD_Clear(White);
  DisplayMenu();
  IntExtOnOffConfig(ENABLE);
}

/**
  * @brief  Checks if the bitmap files (slides + icons) are already loaded in the NOR FLASH.
  * @param  None
  * @retval None
  */
uint32_t CheckBitmapFiles(void)
{
  uint32_t index = 0;
  uint8_t Tab[6];
  uint32_t Icons128Addr[3] = {USB_ICON, ALARM_ICON, WATCH_ICON};

  uint32_t GPIOD_CRL = GPIOD->CRL,  GPIOD_CRH = GPIOD->CRH;
  uint32_t GPIOE_CRL = GPIOE->CRL,  GPIOE_CRH = GPIOE->CRH;
  uint32_t GPIOF_CRL = GPIOF->CRL,  GPIOF_CRH = GPIOF->CRH;
  uint32_t GPIOG_CRL = GPIOG->CRL,  GPIOG_CRH = GPIOG->CRH;
  
  /* Write/read to/from FSMC SRAM memory  *************************************/
  /* Enable the FSMC Clock */
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  
  /* Configure FSMC Bank1 NOR/SRAM2 */
  NOR_Init();
  
  /* Read NOR memory ID */
  NOR_ReadID(&NOR_ID);

  NOR_ReturnToReadMode();


  Tab[0] = 0x00;
  Tab[1] = 0x00;
  Tab[2] = 0x00;
  Tab[3] = 0x00;
  Tab[4] = 0x00;
  Tab[5] = 0x00;

  for(index = 0; index < 14; index++)
  {
    /* Read bitmap size */
    Media_BufferRead(Tab, SlideAddr[index], 6);
    RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
    if(Buffercmp(Tab, SlidesCheck, 5)!= 0) return 1;
    Tab[0] = 0x00;
    Tab[1] = 0x00;
    Tab[2] = 0x00;
    Tab[3] = 0x00;
    Tab[4] = 0x00;
    Tab[5] = 0x00;
  }
  /* Read bitmap size */
  Media_BufferRead(Tab, ST_LOGO, 6);
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  if(Buffercmp(Tab, SlidesCheck, 5)!= 0) return 1;
  Tab[0] = 0x00;
  Tab[1] = 0x00;
  Tab[2] = 0x00;
  Tab[3] = 0x00;
  Tab[4] = 0x00;
  Tab[5] = 0x00;
  /* Read bitmap size */
  Media_BufferRead(Tab, HELP, 6);
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  if(Buffercmp(Tab, SlidesCheck, 5)!= 0) return 1;
  Tab[0] = 0x00;
  Tab[1] = 0x00;
  Tab[2] = 0x00;
  Tab[3] = 0x00;
  Tab[4] = 0x00;
  Tab[5] = 0x00;

  for(index = 0; index < 8; index++)
  {
    /* Read bitmap size */
    Media_BufferRead(Tab, IconsAddr[index], 6);
    RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
    if(Buffercmp(Tab, Icons64Check, 5)!= 0) return 1;
    Tab[0] = 0x00;
    Tab[1] = 0x00;
    Tab[2] = 0x00;
    Tab[3] = 0x00;
    Tab[4] = 0x00;
    Tab[5] = 0x00;
  }

  for(index = 0; index < 3; index++)
  {
    /* Read bitmap size */
    Media_BufferRead(Tab, Icons128Addr[index], 6);
    RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
    if(Buffercmp(Tab, Icons128Check, 5)!= 0) return 1;
    Tab[0] = 0x00;
    Tab[1] = 0x00;
    Tab[2] = 0x00;
    Tab[3] = 0x00;
    Tab[4] = 0x00;
    Tab[5] = 0x00;
  }
  GPIOD->CRL = GPIOD_CRL;
  GPIOD->CRH = GPIOD_CRH;
  GPIOE->CRL = GPIOE_CRL;
  GPIOE->CRH = GPIOE_CRH;
  GPIOF->CRL = GPIOF_CRL;
  GPIOF->CRH = GPIOF_CRH;
  GPIOG->CRL = GPIOG_CRL;
  GPIOG->CRH = GPIOG_CRH;
  RCC_AHBPeriphClockCmd(RCC_AHBPeriph_FSMC, ENABLE);
  return 0;
}

/**
  * @brief  Compares two buffers.
  * @param  pBuffer1, pBuffer2: buffers to be compared.
*           BufferLength: buffer's length
  * @retval 0: pBuffer1 identical to pBuffer2
  *         1: pBuffer1 differs from pBuffer2
  */
static uint8_t Buffercmp(uint8_t* pBuffer1, uint8_t* pBuffer2, uint16_t BufferLength)
{
  while(BufferLength--)
  {
    if(*pBuffer1 != *pBuffer2)
    {
      return 1;
    }

    pBuffer1++;
    pBuffer2++;
  }

  return 0;
}

/**
  * @brief  Configure the ADC1.
  * @param  None
  * @retval None
  */
static void ADC_Config(void)
{
  ADC_InitTypeDef ADC_InitStructure;

  /* ADC1 configuration ------------------------------------------------------*/
  ADC_InitStructure.ADC_Mode = ADC_Mode_Independent;
  ADC_InitStructure.ADC_ScanConvMode = ENABLE;
  ADC_InitStructure.ADC_ContinuousConvMode = ENABLE;
  ADC_InitStructure.ADC_ExternalTrigConv = ADC_ExternalTrigConv_None;
  ADC_InitStructure.ADC_DataAlign = ADC_DataAlign_Right;
  ADC_InitStructure.ADC_NbrOfChannel = 1;
  ADC_Init(ADC1, &ADC_InitStructure);

  /* ADC1 regular channel14 configuration */ 
  ADC_RegularChannelConfig(ADC1, ADC_Channel_14, 1, ADC_SampleTime_55Cycles5);
 
  /* Enable ADC1 */
  ADC_Cmd(ADC1, ENABLE);
 
  /* Start ADC1 Software Conversion */ 
  ADC_SoftwareStartConvCmd(ADC1, ENABLE);
}

/**
  * @brief  This function is used to convert the low nibble of an unsigned byte 
  *        (0-F hex) to ASCII.
  * @param  byte: byte to convert to ASCII.
  * @retval ASCII value result of the conversion.
  */
static uint8_t HexToAsciiLow(uint8_t byte)
{
  /* Keep lower nibble only */
  byte = byte & 0x0F;
  /* If the ascii is a number */	
  if (byte <= 0x09)
  {
    /* Add 0x30 to its ascii */
    return(byte + 0x30);
  }
  else
  {
    /* Add 0x37 to its ascii */
    return (byte + 0x37);
  }
}

/**
  * @brief  This function is used to convert the high nibble of an unsigned byte
  *         (0-F hex) to ASCII.
  * @param  byte: byte to convert to ASCII.
  * @retval ASCII value result of the conversion.
  */
static uint8_t HexToAsciiHigh(uint8_t byte)
{
  /* Keep upper nibble only */
  byte = byte & 0xF0;	
  byte = byte >> 4;
  /* If the ascii is a number */
  if (byte <= 0x09)
  {
    /* Add 0x30 to display its ascii */
    return(byte + 0x30);
  }
  else
  {
    /* Add 0x37 to display its ascii */
    return (byte + 0x37);
  }
}

/**
  * @brief  Retruns the SmartCardStatus variable value.
  * @param  None
  * @retval SmartCardStatus
  */
uint32_t Get_SmartCardStatus(void)
{
  return SmartCardStatus;
}

/**
  * @brief  Sets the CardInserted variable.
  * @param  None
  * @retval None
  */
void Set_CardInserted(void)
{
  CardInserted = 1;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
