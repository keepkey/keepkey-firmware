#ifdef KEEPKEY_PROTOTYPE
/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file keepkey_mesg.c
/// USB message interface for Keepkey.
///
/// Currently this interface just enables the host to write to and read from
/// a buffer inside the Keepkey device.  Ultimately, we may enhance this to
/// support some sort of command interface.  The simple read/write buffer
/// would become a command buffer upon which a Keepkey command interpreter
/// operates.


//================================ INCLUDES ===================================
#include "carbon.h"
#include "hw_config.h"
#include "keepkey_mesg.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================

/// Keepkey message length.
#define KEEPKEY_MESSAGE_LENGTH  256

/// Keepkey commands (from the host perspective).
#define HOST_WRITE_CMD          'w'
#define HOST_READ_CMD           'r'

/// Index to elements in the USB receive buffer.
#define IDX_MESSAGE_TYPE        0   /// Host read or host write command.
#define IDX_MESSAGE_LENGTH      1   /// Number of bytes to read/write.
#define IDX_MESSAGE_OFFSET      2   /// Offset into Keepkey message buffer.
#define IDX_MESSAGE_BODY        3   /// First byte of message being written.


//=============================== VARIABLES ===================================

/// Keepkey message buffer, containing the entire keepkey message from/to the
/// host.  Multiple USB transfers may be needed to read or write the message
/// buffer.
static uint8_t keepkeyMessageBuffer[ KEEPKEY_MESSAGE_LENGTH ];

/// Pointer to next unused byte in Keepkey message buffer.
//static uint8_t* pBufferUnused;


//====================== PRIVATE FUNCTION DECLARATIONS ========================


/*
//-----------------------------------------------------------------------------
/// __One_line_summary_of_function
///
/// __Detailed_description
///
/// @return __Describe_return_value
///
/// @callgraph
/// @callergraph
//-----------------------------------------------------------------------------
static __Type
__PrivateFunctionName (
    __Type __Param1, ///< [in] __Describe_param
    __Type __Param2  ///< [in] __Describe_param
);
*/


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
// See keepkey_mesg.h for public interface.
///
void
KK_HandleUsbMessage (
    __IO uint8_t* recv_buffer,
    __IO uint32_t recv_length
)
{
    /// @todo (LS): Implement ASSERT
    // ASSERT( recv_buffer );

    uint16_t count;             // Byte counter.
    uint16_t offset;            // Offset into keepkey message buffer.
    uint8_t* pKeyBuf;           // Pointer to Keepkey message buffer.
    __IO uint8_t* pUsbBuf;      // Pointer to USB receive buffer.

    // If the received message is complete enough to be valid,
    if ( IDX_MESSAGE_BODY <= recv_length )
    {
        // Get count from USB message.
        count = recv_buffer[ IDX_MESSAGE_LENGTH ];

        // Get offset into keepkey message buffer (staying within the buffer).
        offset = recv_buffer[IDX_MESSAGE_OFFSET];
        offset = MIN ( offset, ARRAY_LENGTH(keepkeyMessageBuffer) );

        // Skip the message preamble during copying.
        recv_length = recv_length - IDX_MESSAGE_BODY;

        // Switch on message type (read/write).
        switch ( recv_buffer[ IDX_MESSAGE_TYPE ] )
        {
            case HOST_WRITE_CMD:

                // Copy bytes from USB receive buffer to Keepkey message buffer.
                // Only copy as many bytes as were actually received.
                pUsbBuf = & ( recv_buffer[ IDX_MESSAGE_BODY ] );
                while ( count-- && recv_length-- && offset < ARRAY_LENGTH(keepkeyMessageBuffer) )
                {
                    keepkeyMessageBuffer[ offset++ ] = *pUsbBuf++;
                }
                break;

            case HOST_READ_CMD:

                // Point to offset in Keepkey message buffer.
                pKeyBuf = & ( keepkeyMessageBuffer[ offset ] );

                // Limit the number of bytes to be copied to stay within
                // the message buffer.
                if ( ARRAY_LENGTH(keepkeyMessageBuffer) < offset + count )
                {
                    count = ARRAY_LENGTH(keepkeyMessageBuffer) - offset;
                }

                // Send bytes from Keepkey message buffer to host.
                CDC_Send_DATA ( (unsigned char*) pKeyBuf, count );
                break;

            default:
                break;
        }
    }
}


/*
//-----------------------------------------------------------------------------
// See private function declaration for interface.
//
static __Type
__PrivateFunctionName (
    __Type __Param1,
    __Type __Param2
);
{
    ASSERT(__Validate_incoming_parameters);
}
*/


#endif // KEEPKEY_PROTOTYPE
