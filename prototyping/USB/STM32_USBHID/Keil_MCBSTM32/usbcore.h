/*----------------------------------------------------------------------------
 *      U S B  -  K e r n e l
 *----------------------------------------------------------------------------
 *      Name:    USBCORE.H
 *      Purpose: USB Core Definitions
 *      Version: V1.10
 *----------------------------------------------------------------------------
 *      This file is part of the uVision/ARM development tools.
 *      This software may only be used under the terms of a valid, current,
 *      end user licence from KEIL for a compatible version of KEIL software
 *      development tools. Nothing else gives you the right to use it.
 *
 *      Copyright (c) 2005-2007 Keil Software.
 *---------------------------------------------------------------------------*/

#ifndef __USBCORE_H__
#define __USBCORE_H__


/* USB Endpoint Data Structure */
typedef struct _USB_EP_DATA {
  BYTE  *pData;
  WORD   Count;
} USB_EP_DATA;

/* USB Core Global Variables */
extern WORD  USB_DeviceStatus;
extern BYTE  USB_DeviceAddress;
extern BYTE  USB_Configuration;
extern DWORD USB_EndPointMask;
extern DWORD USB_EndPointHalt;
extern BYTE  USB_AltSetting[USB_IF_NUM];

/* USB Endpoint 0 Buffer */
extern BYTE  EP0Buf[USB_MAX_PACKET0];

/* USB Endpoint 0 Data Info */
extern USB_EP_DATA EP0Data;

/* USB Setup Packet */
extern USB_SETUP_PACKET SetupPacket;

/* USB Core Functions */
extern void  USB_ResetCore (void);


#endif  /* __USBCORE_H__ */
