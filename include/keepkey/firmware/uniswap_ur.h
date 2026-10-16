/*
 * This file is part of the KeepKey project.
 *
 * Uniswap Universal Router execute() decoder. Pure parsing: no UI, no state.
 * A certified ClearSign entry selects it for one router on one chain; the
 * device then reads every value it shows from the calldata it signs.
 */

#ifndef KEEPKEY_FIRMWARE_UNISWAP_UR_H
#define KEEPKEY_FIRMWARE_UNISWAP_UR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Plan steps per call (a V4 swap with a fee is two). 997 of the 1,000 calls
 * in the D-021 sample need at most 6. */
#define UR_MAX_STEPS 6
/* Distinct non-zero V4 hook contracts per call; each is shown. */
#define UR_MAX_HOOKS 3
/* PathKeys per V4 swap. */
#define UR_V4_MAX_PATH 4

typedef enum {
  UR_V3_SWAP_EXACT_IN,
  UR_V3_SWAP_EXACT_OUT,
  UR_V2_SWAP_EXACT_IN,
  UR_V2_SWAP_EXACT_OUT,
  UR_PERMIT2_PERMIT,
  UR_WRAP_ETH,
  UR_UNWRAP_WETH,
  UR_SWEEP,
  UR_PAY_PORTION,
  UR_TRANSFER,
  /* One V4_SWAP command (actions SWAP_EXACT_IN/OUT, SETTLE, TAKE): the same
   * fields as a V3 swap. token_in/token_out 0 is native ETH. */
  UR_V4_SWAP_EXACT_IN,
  UR_V4_SWAP_EXACT_OUT,
  /* The V4 swap's TAKE_PORTION, right after it: token_in is the currency,
   * recipient the fee recipient, amount the bips. */
  UR_V4_TAKE_PORTION,
} UrKind;

/* Recipient constants the router substitutes (Constants.sol). */
#define UR_RECIPIENT_MSG_SENDER 1
#define UR_RECIPIENT_ADDRESS_THIS 2

typedef struct {
  UrKind kind;
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
} UrStep;

typedef struct {
  uint8_t n;
  UrStep steps[UR_MAX_STEPS];
  bool has_deadline;
  uint64_t deadline;
  /* Every distinct non-zero V4 pool hook in the call, in path order. */
  uint8_t n_hooks;
  uint8_t hooks[UR_MAX_HOOKS][20];
} UrPlan;

/* Streaming decode of execute(bytes,bytes[],uint256) and execute(bytes,bytes[])
 * as the calldata arrives, in chunks of any size: no copy of the call is held,
 * only the plan being built and the offsets still to be reached.
 *
 * The encoding must be laid out in order: the commands, then the inputs
 * array, its elements in index order, and inside each element its dynamic
 * tail after its head words. Every offset points at or past the byte the
 * decoder has reached, and an element starts at or past the previous
 * element's end. Bytes in between, and after the last element, are not read
 * (Solidity's abi.decode ignores them too). An offset pointing backwards or
 * into a previous element is refused. */
typedef struct {
  UrPlan* plan;
  uint32_t total; /* calldata length */
  uint32_t pos;   /* calldata bytes received */
  uint32_t at;    /* where the next field starts; bytes before it are skipped */
  uint32_t base;  /* the current input's payload (or the commands offset) */
  uint32_t len;   /* the current input's payload length */
  uint32_t heads; /* inputs: the first element head (or the inputs offset) */
  uint32_t elem[UR_MAX_STEPS]; /* element offsets, relative to `heads` */
  uint32_t n;                  /* dynamic tail: path bytes or path addresses */
  uint32_t k;                  /* index into the commands or the dynamic tail */
  uint8_t word[32];
  uint8_t got;
  uint8_t state;
  uint8_t field; /* head word of the current input */
  uint8_t step;  /* current input */
  uint8_t ncmds;
  uint8_t cmds[UR_MAX_STEPS];
  uint8_t nsteps; /* plan steps written (a V4 fee adds one) */
  uint8_t pstep;  /* the current input's plan step */
  bool failed;
  /* V4_SWAP: abi.encode(bytes actions, bytes[] params), one level down. */
  struct {
    uint32_t heads; /* params: the first element head (or the params offset) */
    uint32_t elem[4]; /* param offsets, relative to `heads` */
    uint32_t base;    /* the current param's payload */
    uint32_t len;
    uint32_t sw;                 /* swap struct, relative to `base` */
    uint32_t path;               /* swap path: the first PathKey head */
    uint32_t pk[UR_V4_MAX_PATH]; /* PathKey offsets, relative to `path` */
    uint32_t pkb;                /* the current PathKey, relative to `base` */
    uint8_t nacts;
    uint8_t acts[4];
    uint8_t act; /* current action */
    uint8_t npath;
    uint8_t settle_cur[20];
    uint8_t take_cur[20];
    bool swap_done;
  } v4;
} UrStream;

/* Starts a decode of a `total`-byte call into `out` (cleared now). */
void ur_stream_begin(UrStream* s, UrPlan* out, size_t total);
/* The next bytes of the call. False once anything was refused; a refusal is
 * final, and more bytes than `total` are refused. */
bool ur_stream_feed(UrStream* s, const uint8_t* data, size_t len);
/* True only when every byte arrived and the whole call decoded; otherwise
 * the plan is cleared, so a caller never shows a partial decode. Returns
 * false on any command or encoding it does not fully understand. */
bool ur_stream_finish(UrStream* s);

/* The whole call at once: begin, one feed, finish. */
bool ur_decode(const uint8_t* calldata, size_t len, UrPlan* out);

/* True for the router's MSG_SENDER / ADDRESS_THIS placeholders. */
bool ur_recipient_is_constant(const uint8_t recipient[20], uint8_t which);

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
  /* V4 pool hooks the swap runs through; each is shown. */
  uint8_t n_hooks;
  uint8_t hooks[UR_MAX_HOOKS][20];
} UrSummary;

/* Reads the plan as token flow through the router and accepts it only if it
 * says, honestly, one thing: the user pays with one asset (msg.value, or one
 * token the swaps marked payerIsUser pull, after an optional Permit2 permit
 * naming this router), and one asset reaches one recipient (directly from
 * swaps, or by SWEEP / UNWRAP_WETH of what the router holds; a SWEEP of
 * the token comes after every swap that leaves it there; leftover ETH
 * may go back to the same recipient). Swaps paid by the router (splits,
 * multi-hop through V2/V3/V4 pools) are free to the user. amount_in is the
 * sum the user pays (msg.value with ETH), amount_out the sum of the
 * minimums every delivery enforces; all swaps exact-in, or all exact-out.
 * At most one fee (PAY_PORTION, or a V4 swap's TAKE_PORTION). `router` is
 * the contract being called; `value` is msg.value, big-endian. False for
 * anything else, so nothing partial is ever shown. */
bool ur_summarize(const UrPlan* plan, const uint8_t router[20],
                  const uint8_t value[32], UrSummary* out);

#endif
