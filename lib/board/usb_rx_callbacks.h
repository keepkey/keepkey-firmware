/* Hardware receive callbacks, shared verbatim with the native USB-driver
 * probe. The probe replaces only the endpoint read and destination callbacks.
 */
static void main_rx_callback(usbd_device* dev, uint8_t ep) {
  (void)ep;
  static CONFIDENTIAL uint8_t buf[64] __attribute__((aligned(4)));
  const int received =
      usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_MAIN_OUT, buf, 64);
  if (received != 64) {
    if (received > 0) msg_reject_short_tiny_packet();
    memzero(buf, sizeof(buf));
    return;
  }
  debugLog(0, "", "main_rx_callback");

  if (user_rx_callback) {
    user_rx_callback(buf, 64);
  }
  memzero(buf, sizeof(buf));
}

static void u2f_rx_callback(usbd_device* dev, uint8_t ep) {
  (void)ep;
  static CONFIDENTIAL uint8_t buf[64] __attribute__((aligned(4)));

  debugLog(0, "", "u2f_rx_callback");
  if (usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_U2F_OUT, buf, 64) != 64) {
    memzero(buf, sizeof(buf));
    return;
  }

  if (user_u2f_rx_callback) {
    user_u2f_rx_callback(tiny, (const U2FHID_FRAME*)(void*)buf);
  }
  memzero(buf, sizeof(buf));
}

#if DEBUG_LINK
static void debug_rx_callback(usbd_device* dev, uint8_t ep) {
  (void)ep;
  static uint8_t buf[64] __attribute__((aligned(4)));
  const int received =
      usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_DEBUG_OUT, buf, 64);
  if (received != 64) {
    if (received > 0) msg_reject_short_tiny_packet();
    memzero(buf, sizeof(buf));
    return;
  }
  debugLog(0, "", "debug_rx_callback");

  if (user_debug_rx_callback) {
    user_debug_rx_callback(buf, 64);
  }
  memzero(buf, sizeof(buf));
}
#endif
