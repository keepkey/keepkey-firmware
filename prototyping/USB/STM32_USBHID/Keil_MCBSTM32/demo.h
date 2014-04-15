/*----------------------------------------------------------------------------
 *      Name:    DEMO.H
 *      Purpose: USB HID Demo Definitions
 *      Version: V1.10
 *----------------------------------------------------------------------------
 *      This file is part of the uVision/ARM development tools.
 *      This software may only be used under the terms of a valid, current,
 *      end user licence from KEIL for a compatible version of KEIL software
 *      development tools. Nothing else gives you the right to use it.
 *
 *      Copyright (c) 2005-2007 Keil Software.
 *---------------------------------------------------------------------------*/

/* Push Button Definitions */
#define S3             0x2000                     // PC13: S3
#define S2             0x0001                     // PA0 : S2

/* HID Demo Variables */
extern BYTE   InReport;
extern BYTE   OutReport;

/* HID Demo Functions */
extern void GetInReport  (void);
extern void SetOutReport (void);
