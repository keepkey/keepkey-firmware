/* Test oracle: the 7.16 Universal Router decoder and summarizer as they were
 * at 162bc884f (buffered, V2/V3 only), with their own types so later changes
 * to uniswap_ur.h cannot move them. See uniswap_ur_oracle.c. */
#ifndef UNITTESTS_FIRMWARE_UNISWAP_UR_ORACLE_H
#define UNITTESTS_FIRMWARE_UNISWAP_UR_ORACLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define URO_MAX_STEPS 4

typedef enum {
  URO_V3_SWAP_EXACT_IN,
  URO_V3_SWAP_EXACT_OUT,
  URO_V2_SWAP_EXACT_IN,
  URO_V2_SWAP_EXACT_OUT,
  URO_PERMIT2_PERMIT,
  URO_WRAP_ETH,
  URO_UNWRAP_WETH,
  URO_SWEEP,
  URO_PAY_PORTION,
  URO_TRANSFER,
} UroKind;

/* Recipient constants the router substitutes (Constants.sol). */
#define URO_RECIPIENT_MSG_SENDER 1
#define URO_RECIPIENT_ADDRESS_THIS 2

typedef struct {
  UroKind kind;
  /* Swaps: endpoints of the path. PERMIT2_PERMIT / SWEEP / PAY_PORTION /
   * TRANSFER: token_in is the token. */
  uint8_t token_in[20];
  /* Swaps: output token. PERMIT2_PERMIT: the spender (no output token). */
  uint8_t token_out[20];
  /* As encoded; 0x..01 and 0x..02 are the router's constants. */
  uint8_t recipient[20];
  /* Swaps: exact amount (in for EXACT_IN, out for EXACT_OUT).
   * WRAP / UNWRAP / SWEEP: minimum. PAY_PORTION: bips. TRANSFER: value.
   * PERMIT2_PERMIT: allowance (uint160). Big-endian. */
  uint8_t amount[32];
  /* Swaps: the limit (minimum out for EXACT_IN, maximum in for EXACT_OUT). */
  uint8_t limit[32];
  /* PERMIT2_PERMIT only. */
  uint64_t expiration;
  bool payer_is_user;
} UroStep;

typedef struct {
  uint8_t n;
  UroStep steps[URO_MAX_STEPS];
  bool has_deadline;
  uint64_t deadline;
} UroPlan;

/* What the user is asked to approve: one swap, how it is paid, where the
 * output goes, and any Permit2 allowance or fee riding along. */
typedef struct {
  bool exact_in;
  bool in_is_eth;  /* msg.value wrapped by the router */
  bool out_is_eth; /* output unwrapped to ETH */
  uint8_t token_in[20];
  uint8_t token_out[20];
  /* exact_in: spend exactly amount_in, receive at least amount_out.
   * !exact_in: spend at most amount_in, receive exactly amount_out. */
  uint8_t amount_in[32];
  uint8_t amount_out[32];
  bool recipient_is_sender;
  uint8_t recipient[20];
  bool has_permit;
  uint8_t permit_token[20];
  uint8_t permit_amount[32];
  uint64_t permit_expiration;
  bool has_fee;
  uint16_t fee_bips;
  uint8_t fee_recipient[20];
} UroSummary;

bool ur_oracle_decode(const uint8_t* calldata, size_t len, UroPlan* out);
bool ur_oracle_summarize(const UroPlan* plan, const uint8_t router[20],
                         const uint8_t value[32], UroSummary* out);

#ifdef __cplusplus
}
#endif

#endif
