/*----------------------------------------------------------------------------
 *      U S B  -  K e r n e l
 *----------------------------------------------------------------------------
 *      Name:    USBCORE.C
 *      Purpose: USB Core Module
 *      Version: V1.10
 *----------------------------------------------------------------------------
 *      This file is part of the uVision/ARM development tools.
 *      This software may only be used under the terms of a valid, current,
 *      end user licence from KEIL for a compatible version of KEIL software
 *      development tools. Nothing else gives you the right to use it.
 *
 *      Copyright (c) 2005-2007 Keil Software.
 *---------------------------------------------------------------------------*/

#include "type.h"

#include "usb.h"
#include "usbcfg.h"
#include "usbhw.h"
#include "usbcore.h"
#include "usbdesc.h"
#include "usbuser.h"

#if (USB_AUDIO)
#include "audio.h"
#include "adcuser.h"
#endif

#if (USB_HID)
#include "hid.h"
#include "hiduser.h"
#endif

#if (USB_MSC)
#include "msc.h"
#include "mscuser.h"
#endif


#pragma diag_suppress 111,1441


WORD  USB_DeviceStatus;
BYTE  USB_DeviceAddress;
BYTE  USB_Configuration;
DWORD USB_EndPointMask;
DWORD USB_EndPointHalt;
BYTE  USB_NumInterfaces;
BYTE  USB_AltSetting[USB_IF_NUM];

BYTE  EP0Buf[USB_MAX_PACKET0];


USB_EP_DATA EP0Data;

USB_SETUP_PACKET SetupPacket;


/*
 *  Reset USB Core
 *    Parameters:      None
 *    Return Value:    None
 */

void USB_ResetCore (void) {

  USB_DeviceStatus  = USB_POWER;
  USB_DeviceAddress = 0;
  USB_Configuration = 0;
  USB_EndPointMask  = 0x00010001;
  USB_EndPointHalt  = 0x00000000;
}


/*
 *  USB Request - Setup Stage
 *    Parameters:      None (global SetupPacket)
 *    Return Value:    None
 */

void USB_SetupStage (void) {
  USB_ReadEP(0x00, (BYTE *)&SetupPacket);
}


/*
 *  USB Request - Data In Stage
 *    Parameters:      None (global EP0Data)
 *    Return Value:    None
 */

void USB_DataInStage (void) {
  DWORD cnt;

  if (EP0Data.Count > USB_MAX_PACKET0) {
    cnt = USB_MAX_PACKET0;
  } else {
    cnt = EP0Data.Count;
  }
  cnt = USB_WriteEP(0x80, EP0Data.pData, cnt);
  EP0Data.pData += cnt;
  EP0Data.Count -= cnt;
}


/*
 *  USB Request - Data Out Stage
 *    Parameters:      None (global EP0Data)
 *    Return Value:    None
 */

void USB_DataOutStage (void) {
  DWORD cnt;

  cnt = USB_ReadEP(0x00, EP0Data.pData);
  EP0Data.pData += cnt;
  EP0Data.Count -= cnt;
}


/*
 *  USB Request - Status In Stage
 *    Parameters:      None
 *    Return Value:    None
 */

void USB_StatusInStage (void) {
  USB_WriteEP(0x80, NULL, 0);
}


/*
 *  USB Request - Status Out Stage
 *    Parameters:      None
 *    Return Value:    None
 */

void USB_StatusOutStage (void) {
  USB_ReadEP(0x00, EP0Buf);
}


/*
 *  Get Status USB Request
 *    Parameters:      None (global SetupPacket)
 *    Return Value:    TRUE - Success, FALSE - Error
 */

__inline BOOL USB_GetStatus (void) {
  DWORD n, m;

  switch (SetupPacket.bmRequestType.BM.Recipient) {
    case REQUEST_TO_DEVICE:
      EP0Data.pData = (BYTE *)&USB_DeviceStatus;
      USB_DataInStage();
      break;
    case REQUEST_TO_INTERFACE:
      if ((USB_Configuration != 0) && (SetupPacket.wIndex.WB.L < USB_NumInterfaces)) {
        *((__packed WORD *)EP0Buf) = 0;
        EP0Data.pData = EP0Buf;
        USB_DataInStage();
      } else {
        return (FALSE);
      }
      break;
    case REQUEST_TO_ENDPOINT:
      n = SetupPacket.wIndex.WB.L & 0x8F;
      m = (n & 0x80) ? ((1 << 16) << (n & 0x0F)) : (1 << n);
      if (((USB_Configuration != 0) || ((n & 0x0F) == 0)) && (USB_EndPointMask & m)) {
        *((__packed WORD *)EP0Buf) = (USB_EndPointHalt & m) ? 1 : 0;
        EP0Data.pData = EP0Buf;
        USB_DataInStage();
      } else {
        return (FALSE);
      }
      break;
    default:
      return (FALSE);
  }
  return (TRUE);
}


/*
 *  Set/Clear Feature USB Request
 *    Parameters:      sc:    0 - Clear, 1 - Set
 *                            None (global SetupPacket)
 *    Return Value:    TRUE - Success, FALSE - Error
 */

__inline BOOL USB_SetClrFeature (DWORD sc) {
  DWORD n, m;

  switch (SetupPacket.bmRequestType.BM.Recipient) {
    case REQUEST_TO_DEVICE:
      if (SetupPacket.wValue.W == USB_FEATURE_REMOTE_WAKEUP) {
        if (sc) {
          USB_WakeUpCfg(TRUE);
          USB_DeviceStatus |=  USB_GETSTATUS_REMOTE_WAKEUP;
        } else {
          USB_WakeUpCfg(FALSE);
          USB_DeviceStatus &= ~USB_GETSTATUS_REMOTE_WAKEUP;
        }
      } else {
        return (FALSE);
      }
      break;
    case REQUEST_TO_INTERFACE:
      return (FALSE);
    case REQUEST_TO_ENDPOINT:
      n = SetupPacket.wIndex.WB.L & 0x8F;
      m = (n & 0x80) ? ((1 << 16) << (n & 0x0F)) : (1 << n);
      if ((USB_Configuration != 0) && ((n & 0x0F) != 0) && (USB_EndPointMask & m)) {
        if (SetupPacket.wValue.W == USB_FEATURE_ENDPOINT_STALL) {
          if (sc) {
            USB_SetStallEP(n);
            USB_EndPointHalt |=  m;
          } else {
            USB_ClrStallEP(n);
            USB_EndPointHalt &= ~m;
          }
        } else {
          return (FALSE);
        }
      } else {
        return (FALSE);
      }
      break;
    default:
      return (FALSE);
  }
  return (TRUE);
}


/*
 *  Get Descriptor USB Request
 *    Parameters:      None (global SetupPacket)
 *    Return Value:    TRUE - Success, FALSE - Error
 */

__inline BOOL USB_GetDescriptor (void) {
  BYTE  *pD;
  DWORD len, n;

  switch (SetupPacket.bmRequestType.BM.Recipient) {
    case REQUEST_TO_DEVICE:
      switch (SetupPacket.wValue.WB.H) {
        case USB_DEVICE_DESCRIPTOR_TYPE:
          EP0Data.pData = (BYTE *)USB_DeviceDescriptor;
          len = USB_DEVICE_DESC_SIZE;
          break;
        case USB_CONFIGURATION_DESCRIPTOR_TYPE:
          pD = (BYTE *)USB_ConfigDescriptor;
          for (n = 0; n != SetupPacket.wValue.WB.L; n++) {
            if (((USB_CONFIGURATION_DESCRIPTOR *)pD)->bLength != 0) {
              pD += ((USB_CONFIGURATION_DESCRIPTOR *)pD)->wTotalLength;
            }
          }
          if (((USB_CONFIGURATION_DESCRIPTOR *)pD)->bLength == 0) {
            return (FALSE);
          }
          EP0Data.pData = pD;
          len = ((USB_CONFIGURATION_DESCRIPTOR *)pD)->wTotalLength;
          break;
        case USB_STRING_DESCRIPTOR_TYPE:
          EP0Data.pData = (BYTE *)USB_StringDescriptor + SetupPacket.wValue.WB.L;
          len = ((USB_STRING_DESCRIPTOR *)EP0Data.pData)->bLength;
          break;
        default:
          return (FALSE);
      }
      break;
    case REQUEST_TO_INTERFACE:
      switch (SetupPacket.wValue.WB.H) {
#if USB_HID
        case HID_HID_DESCRIPTOR_TYPE:
          if (SetupPacket.wIndex.WB.L != USB_HID_IF_NUM) {
            return (FALSE);    /* Only Single HID Interface is supported */
          }
          EP0Data.pData = (BYTE *)USB_ConfigDescriptor + HID_DESC_OFFSET;
          len = HID_DESC_SIZE;
          break;
        case HID_REPORT_DESCRIPTOR_TYPE:
          if (SetupPacket.wIndex.WB.L != USB_HID_IF_NUM) {
            return (FALSE);    /* Only Single HID Interface is supported */
          }
          EP0Data.pData = (BYTE *)HID_ReportDescriptor;
          len = HID_ReportDescSize;
          break;
        case HID_PHYSICAL_DESCRIPTOR_TYPE:
          return (FALSE);      /* HID Physical Descriptor is not supported */
#endif
        default:
          return (FALSE);
      }
      break;
    default:
      return (FALSE);
  }

  if (EP0Data.Count > len) {
    EP0Data.Count = len;
  }
  USB_DataInStage();

  return (TRUE);
}


/*
 *  Set Configuration USB Request
 *    Parameters:      None (global SetupPacket)
 *    Return Value:    TRUE - Success, FALSE - Error
 */

__inline BOOL USB_SetConfiguration (void) {
  USB_COMMON_DESCRIPTOR *pD;
  DWORD                  alt, n, m;

  if (SetupPacket.wValue.WB.L) {
    pD = (USB_COMMON_DESCRIPTOR *)USB_ConfigDescriptor;
    while (pD->bLength) {
      switch (pD->bDescriptorType) {
        case USB_CONFIGURATION_DESCRIPTOR_TYPE:
          if (((USB_CONFIGURATION_DESCRIPTOR *)pD)->bConfigurationValue == SetupPacket.wValue.WB.L) {
            USB_Configuration = SetupPacket.wValue.WB.L;
            USB_NumInterfaces = ((USB_CONFIGURATION_DESCRIPTOR *)pD)->bNumInterfaces;
            for (n = 0; n < USB_IF_NUM; n++) {
              USB_AltSetting[n] = 0;
            }
            for (n = 1; n < 16; n++) {
              if (USB_EndPointMask & (1 << n)) {
                USB_DisableEP(n);
              }
              if (USB_EndPointMask & ((1 << 16) << n)) {
                USB_DisableEP(n | 0x80);
              }
            }
            USB_EndPointMask = 0x00010001;
            USB_EndPointHalt = 0x00000000;
            USB_Configure(TRUE);
            if (((USB_CONFIGURATION_DESCRIPTOR *)pD)->bmAttributes & USB_CONFIG_SELF_POWERED) {
              USB_DeviceStatus |=  USB_GETSTATUS_SELF_POWERED;
            } else {
              USB_DeviceStatus &= ~USB_GETSTATUS_SELF_POWERED;
            }
          } else {
            (BYTE *)pD += ((USB_CONFIGURATION_DESCRIPTOR *)pD)->wTotalLength;
            continue;
          }
          break;
        case USB_INTERFACE_DESCRIPTOR_TYPE:
          alt = ((USB_INTERFACE_DESCRIPTOR *)pD)->bAlternateSetting;
          break;
        case USB_ENDPOINT_DESCRIPTOR_TYPE:
          if (alt == 0) {
            n = ((USB_ENDPOINT_DESCRIPTOR *)pD)->bEndpointAddress & 0x8F;
            m = (n & 0x80) ? ((1 << 16) << (n & 0x0F)) : (1 << n);
            USB_EndPointMask |= m;
            USB_ConfigEP((USB_ENDPOINT_DESCRIPTOR *)pD);
            USB_EnableEP(n);
            USB_ResetEP(n);
          }
          break;
      }
      (BYTE *)pD += pD->bLength;
    }
  }
  else {
    USB_Configuration = 0;
    for (n = 1; n < 16; n++) {
      if (USB_EndPointMask & (1 << n)) {
        USB_DisableEP(n);
      }
      if (USB_EndPointMask & ((1 << 16) << n)) {
        USB_DisableEP(n | 0x80);
      }
    }
    USB_EndPointMask  = 0x00010001;
    USB_EndPointHalt  = 0x00000000;
    USB_Configure(FALSE);
  }

  if (USB_Configuration == SetupPacket.wValue.WB.L) {
    return (TRUE);
  } else {
    return (FALSE);
  }
}


/*
 *  Set Interface USB Request
 *    Parameters:      None (global SetupPacket)
 *    Return Value:    TRUE - Success, FALSE - Error
 */

__inline BOOL USB_SetInterface (void) {
  USB_COMMON_DESCRIPTOR *pD;
  DWORD                  ifn, alt, old, msk, n, m;
  BOOL                   set;

  if (USB_Configuration == 0) return (FALSE);

  set = FALSE;
  pD  = (USB_COMMON_DESCRIPTOR *)USB_ConfigDescriptor;
  while (pD->bLength) {
    switch (pD->bDescriptorType) {
      case USB_CONFIGURATION_DESCRIPTOR_TYPE:
        if (((USB_CONFIGURATION_DESCRIPTOR *)pD)->bConfigurationValue != USB_Configuration) {
          (BYTE *)pD += ((USB_CONFIGURATION_DESCRIPTOR *)pD)->wTotalLength;
          continue;
        }
        break;
      case USB_INTERFACE_DESCRIPTOR_TYPE:
        ifn = ((USB_INTERFACE_DESCRIPTOR *)pD)->bInterfaceNumber;
        alt = ((USB_INTERFACE_DESCRIPTOR *)pD)->bAlternateSetting;
        msk = 0;
        if ((ifn == SetupPacket.wIndex.WB.L) && (alt == SetupPacket.wValue.WB.L)) {
          set = TRUE;
          old = USB_AltSetting[ifn];
          USB_AltSetting[ifn] = (BYTE)alt;
        }
        break;
      case USB_ENDPOINT_DESCRIPTOR_TYPE:
        if (ifn == SetupPacket.wIndex.WB.L) {
          n = ((USB_ENDPOINT_DESCRIPTOR *)pD)->bEndpointAddress & 0x8F;
          m = (n & 0x80) ? ((1 << 16) << (n & 0x0F)) : (1 << n);
          if (alt == SetupPacket.wValue.WB.L) {
            USB_EndPointMask |=  m;
            USB_EndPointHalt &= ~m;
            USB_ConfigEP((USB_ENDPOINT_DESCRIPTOR *)pD);
            USB_EnableEP(n);
            USB_ResetEP(n);
            msk |= m;
          }
          else if ((alt == old) && ((msk & m) == 0)) {
            USB_EndPointMask &= ~m;
            USB_EndPointHalt &= ~m;
            USB_DisableEP(n);
          }
        }
        break;
    }
    (BYTE *)pD += pD->bLength;
  }
  return (set);
}


/*
 *  USB Endpoint 0 Event Callback
 *    Parameter:       event
 */

void USB_EndPoint0 (DWORD event) {

  switch (event) {

    case USB_EVT_SETUP:
      USB_SetupStage();
      USB_DirCtrlEP(SetupPacket.bmRequestType.BM.Dir);
      EP0Data.Count = SetupPacket.wLength;
      switch (SetupPacket.bmRequestType.BM.Type) {

        case REQUEST_STANDARD:
          switch (SetupPacket.bRequest) {

            case USB_REQUEST_GET_STATUS:
              if (!USB_GetStatus()) {
                goto stall_i;
              }
              break;

            case USB_REQUEST_CLEAR_FEATURE:
              if (!USB_SetClrFeature(0)) {
                goto stall_i;
              }
              USB_StatusInStage();
#if USB_FEATURE_EVENT
              USB_Feature_Event();
#endif
              break;

            case USB_REQUEST_SET_FEATURE:
              if (!USB_SetClrFeature(1)) {
                goto stall_i;
              }
              USB_StatusInStage();
#if USB_FEATURE_EVENT
              USB_Feature_Event();
#endif
              break;

            case USB_REQUEST_SET_ADDRESS:
              switch (SetupPacket.bmRequestType.BM.Recipient) {
                case REQUEST_TO_DEVICE:
                  USB_DeviceAddress = 0x80 | SetupPacket.wValue.WB.L;
                  USB_StatusInStage();
                  break;
                default:
                  goto stall_i;
              }
              break;

            case USB_REQUEST_GET_DESCRIPTOR:
              if (!USB_GetDescriptor()) {
                goto stall_i;
              }
              break;

            case USB_REQUEST_SET_DESCRIPTOR:
/*stall_o:*/  USB_SetStallEP(0x00);
              EP0Data.Count = 0;
              break;

            case USB_REQUEST_GET_CONFIGURATION:
              switch (SetupPacket.bmRequestType.BM.Recipient) {
                case REQUEST_TO_DEVICE:
                  EP0Data.pData = &USB_Configuration;
                  USB_DataInStage();
                  break;
                default:
                  goto stall_i;
              }
              break;

            case USB_REQUEST_SET_CONFIGURATION:
              switch (SetupPacket.bmRequestType.BM.Recipient) {
                case REQUEST_TO_DEVICE:
                  if (!USB_SetConfiguration()) {
                    goto stall_i;
                  }
                  USB_StatusInStage();
#if USB_CONFIGURE_EVENT
                  USB_Configure_Event();
#endif
                  break;
                default:
                  goto stall_i;
              }
              break;

            case USB_REQUEST_GET_INTERFACE:
              switch (SetupPacket.bmRequestType.BM.Recipient) {
                case REQUEST_TO_INTERFACE:
                  if ((USB_Configuration != 0) &&
                      (SetupPacket.wIndex.WB.L < USB_NumInterfaces)) {
                    EP0Data.pData = USB_AltSetting + SetupPacket.wIndex.WB.L;
                    USB_DataInStage();
                  } else {
                    goto stall_i;
                  }
                  break;
                default:
                  goto stall_i;
              }
              break;

            case USB_REQUEST_SET_INTERFACE:
              switch (SetupPacket.bmRequestType.BM.Recipient) {
                case REQUEST_TO_INTERFACE:
                  if (!USB_SetInterface()) {
                    goto stall_i;
                  }
                  USB_StatusInStage();
#if USB_INTERFACE_EVENT
                  USB_Interface_Event();
#endif
                  break;
                default:
                  goto stall_i;
              }
              break;

            default:
              goto stall_i;

          }
          break;

        case REQUEST_CLASS:
#if USB_CLASS
          switch (SetupPacket.bmRequestType.BM.Recipient) {
            case REQUEST_TO_INTERFACE:
#if USB_HID
              if (SetupPacket.wIndex.WB.L == USB_HID_IF_NUM) {
                switch (SetupPacket.bRequest) {
                  case HID_REQUEST_GET_REPORT:
                    if (HID_GetReport()) {
                      EP0Data.pData = EP0Buf;
                      USB_DataInStage();
                      goto class_ok;
                    }
                    break;
                  case HID_REQUEST_SET_REPORT:
                    EP0Data.pData = EP0Buf;
                    goto class_ok;
                  case HID_REQUEST_GET_IDLE:
                    if (HID_GetIdle()) {
                      EP0Data.pData = EP0Buf;
                      USB_DataInStage();
                      goto class_ok;
                    }
                    break;
                  case HID_REQUEST_SET_IDLE:
                    if (HID_SetIdle()) {
                      USB_StatusInStage();
                      goto class_ok;
                    }
                    break;
                  case HID_REQUEST_GET_PROTOCOL:
                    if (HID_GetProtocol()) {
                      EP0Data.pData = EP0Buf;
                      USB_DataInStage();
                      goto class_ok;
                    }
                    break;
                  case HID_REQUEST_SET_PROTOCOL:
                    if (HID_SetProtocol()) {
                      USB_StatusInStage();
                      goto class_ok;
                    }
                    break;
                }
              }
#endif  /* USB_HID */
#if USB_MSC
              if (SetupPacket.wIndex.WB.L == USB_MSC_IF_NUM) {
                switch (SetupPacket.bRequest) {
                  case MSC_REQUEST_RESET:
                    if (MSC_Reset()) {
                      USB_StatusInStage();
                      goto class_ok;
                    }
                    break;
                  case MSC_REQUEST_GET_MAX_LUN:
                    if (MSC_GetMaxLUN()) {
                      EP0Data.pData = EP0Buf;
                      USB_DataInStage();
                      goto class_ok;
                    }
                    break;
                }
              }
#endif  /* USB_MSC */
#if USB_AUDIO
              if ((SetupPacket.wIndex.WB.L == USB_ADC_CIF_NUM)  ||
                  (SetupPacket.wIndex.WB.L == USB_ADC_SIF1_NUM) ||
                  (SetupPacket.wIndex.WB.L == USB_ADC_SIF2_NUM)) {
                if (SetupPacket.bmRequestType.BM.Dir) {
                  if (ADC_IF_GetRequest()) {
                    EP0Data.pData = EP0Buf;
                    USB_DataInStage();
                    goto class_ok;
                  }
                } else {
                  EP0Data.pData = EP0Buf;
                  goto class_ok;
                }
              }
#endif  /* USB_AUDIO */
              goto stall_i;
#if USB_AUDIO
            case REQUEST_TO_ENDPOINT:
              if (SetupPacket.bmRequestType.BM.Dir) {
                if (ADC_EP_GetRequest()) {
                  EP0Data.pData = EP0Buf;
                  USB_DataInStage();
                  goto class_ok;
                }
              } else {
                EP0Data.pData = EP0Buf;
                goto class_ok;
              }
              goto stall_i;
#endif  /* USB_AUDIO */
            default:
              goto stall_i;
          }
class_ok: break;
#else
          goto stall_i;
#endif  /* USB_CLASS */

        case REQUEST_VENDOR:
          goto stall_i;

        default:
stall_i:  USB_SetStallEP(0x80);
          EP0Data.Count = 0;
          break;

      }
      break;

    case USB_EVT_OUT:
      if (SetupPacket.bmRequestType.BM.Dir == 0) {
        if (EP0Data.Count) {
          USB_DataOutStage();
          if (EP0Data.Count == 0) {
            switch (SetupPacket.bmRequestType.BM.Type) {
              case REQUEST_STANDARD:
                goto stall_i;
#if (USB_CLASS)
              case REQUEST_CLASS:
                switch (SetupPacket.bmRequestType.BM.Recipient) {
                  case REQUEST_TO_INTERFACE:
#if USB_HID
                    if (SetupPacket.wIndex.WB.L == USB_HID_IF_NUM) {
                      if (!HID_SetReport()) {
                        goto stall_i;
                      }
                      break;
                    }
#endif
#if USB_AUDIO
                    if ((SetupPacket.wIndex.WB.L == USB_ADC_CIF_NUM)  ||
                        (SetupPacket.wIndex.WB.L == USB_ADC_SIF1_NUM) ||
                        (SetupPacket.wIndex.WB.L == USB_ADC_SIF2_NUM)) {
                      if (!ADC_IF_SetRequest()) {
                        goto stall_i;
                      }
                      break;
                    }
#endif
                    goto stall_i;
                  case REQUEST_TO_ENDPOINT:
#if USB_AUDIO
                    if (ADC_EP_SetRequest()) break;
#endif
                    goto stall_i;
                  default:
                    goto stall_i;
                }
                break;
#endif
              default:
                goto stall_i;
            }
            USB_StatusInStage();
          }
        }
      } else {
        USB_StatusOutStage();
      }
      break;

    case USB_EVT_IN:
      if (SetupPacket.bmRequestType.BM.Dir == 1) {
        USB_DataInStage();
      } else {
        if (USB_DeviceAddress & 0x80) {
          USB_DeviceAddress &= 0x7F;
          USB_SetAddress(USB_DeviceAddress);
        }
      }
      break;

    case USB_EVT_IN_STALL:
      USB_ClrStallEP(0x80);
      break;

    case USB_EVT_OUT_STALL:
      USB_ClrStallEP(0x00);
      break;

  }
}
