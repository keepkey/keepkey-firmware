/*----------------------------------------------------------------------------
 *      U S B  -  K e r n e l
 *----------------------------------------------------------------------------
 *      Name:    USBHW.H
 *      Purpose: USB Hardware Layer Definitions
 *      Version: V1.10
 *----------------------------------------------------------------------------
 *      This file is part of the uVision/ARM development tools.
 *      This software may only be used under the terms of a valid, current,
 *      end user licence from KEIL for a compatible version of KEIL software
 *      development tools. Nothing else gives you the right to use it.
 *
 *      Copyright (c) 2005-2007 Keil Software.
 *---------------------------------------------------------------------------*/

#ifndef __USBHW_H__
#define __USBHW_H__


/* USB Hardware Functions */
extern void  USB_Init       (void);
extern void  USB_Connect    (BOOL  con);
extern void  USB_Reset      (void);
extern void  USB_Suspend    (void);
extern void  USB_Resume     (void);
extern void  USB_WakeUp     (void);
extern void  USB_WakeUpCfg  (BOOL  cfg);
extern void  USB_SetAddress (DWORD adr);
extern void  USB_Configure  (BOOL cfg);
extern void  USB_ConfigEP   (USB_ENDPOINT_DESCRIPTOR *pEPD);
extern void  USB_DirCtrlEP  (DWORD dir);
extern void  USB_EnableEP   (DWORD EPNum);
extern void  USB_DisableEP  (DWORD EPNum);
extern void  USB_ResetEP    (DWORD EPNum);
extern void  USB_SetStallEP (DWORD EPNum);
extern void  USB_ClrStallEP (DWORD EPNum);
extern DWORD USB_ReadEP     (DWORD EPNum, BYTE *pData);
extern DWORD USB_WriteEP    (DWORD EPNum, BYTE *pData, DWORD cnt);
extern DWORD USB_GetFrame   (void);


#endif  /* __USBHW_H__ */
