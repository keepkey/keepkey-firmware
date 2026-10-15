/*
 * This file is part of the KeepKey project.
 *
 * TEST ORACLE ONLY, never linked into firmware. lib/firmware/uniswap_ur.c as
 * it was at 162bc884f: the buffered decoder (ur_decode) and the V2/V3
 * summarizer (ur_summarize), unchanged but for names. The differential tests
 * in uniswap_ur.cpp require the streaming decoder and the current summarizer
 * to agree with them wherever these accept.
 */

#include "uniswap_ur_oracle.h"

#include <string.h>

/* Commands.sol */
#define CMD_V3_SWAP_EXACT_IN 0x00
#define CMD_V3_SWAP_EXACT_OUT 0x01
#define CMD_SWEEP 0x04
#define CMD_TRANSFER 0x05
#define CMD_PAY_PORTION 0x06
#define CMD_V2_SWAP_EXACT_IN 0x08
#define CMD_V2_SWAP_EXACT_OUT 0x09
#define CMD_PERMIT2_PERMIT 0x0a
#define CMD_WRAP_ETH 0x0b
#define CMD_UNWRAP_WETH 0x0c
/* Bit 7 is FLAG_ALLOW_REVERT; bit 6 is unused. Either set: not decoded. */
#define CMD_FLAGS 0xc0

#define V3_HOP 23 /* fee(3) + token(20) */

typedef struct {
  const uint8_t* p;
  size_t len;
} Span;

static bool word_at(Span s, size_t off, const uint8_t** w) {
  if (off > s.len || s.len - off < 32) return false;
  *w = s.p + off;
  return true;
}

/* A word holding an integer no wider than `bytes`. Offsets and lengths use 4:
 * size_t is 32-bit on the device, so a wider value would wrap there while a
 * 64-bit host (and the router) read it in full. */
static bool uint_at(Span s, size_t off, size_t bytes, uint64_t* out) {
  const uint8_t* w;
  if (!word_at(s, off, &w) || bytes > 8) return false;
  for (size_t i = 0; i < 32 - bytes; i++) {
    if (w[i] != 0) return false;
  }
  uint64_t v = 0;
  for (size_t i = 32 - bytes; i < 32; i++) v = (v << 8) | w[i];
  *out = v;
  return true;
}

static bool address_at(Span s, size_t off, uint8_t out[20]) {
  const uint8_t* w;
  if (!word_at(s, off, &w)) return false;
  for (int i = 0; i < 12; i++) {
    if (w[i] != 0) return false;
  }
  memcpy(out, w + 12, 20);
  return true;
}

static bool bool_at(Span s, size_t off, bool* out) {
  uint64_t v;
  if (!uint_at(s, off, 1, &v) || v > 1) return false;
  *out = v == 1;
  return true;
}

static bool u256_at(Span s, size_t off, uint8_t out[32]) {
  const uint8_t* w;
  if (!word_at(s, off, &w)) return false;
  memcpy(out, w, 32);
  return true;
}

/* uint160 (Permit2 amounts): top 12 bytes zero. */
static bool u160_at(Span s, size_t off, uint8_t out[32]) {
  const uint8_t* w;
  if (!word_at(s, off, &w)) return false;
  for (int i = 0; i < 12; i++) {
    if (w[i] != 0) return false;
  }
  memcpy(out, w, 32);
  return true;
}

/* Dynamic `bytes` whose head word is at `head`: offset relative to s.p. */
static bool bytes_at(Span s, size_t head, Span* out) {
  uint64_t off, n;
  if (!uint_at(s, head, 4, &off) || !uint_at(s, (size_t)off, 4, &n)) {
    return false;
  }
  size_t start = (size_t)off + 32;
  if (start > s.len || n > s.len - start) return false;
  out->p = s.p + start;
  out->len = (size_t)n;
  return true;
}

/* V3 path: token(20) (fee(3) token(20))+ — at least one hop. */
static bool v3_path_ends(Span path, uint8_t first[20], uint8_t last[20]) {
  if (path.len < 20 + V3_HOP || (path.len - 20) % V3_HOP != 0) return false;
  memcpy(first, path.p, 20);
  memcpy(last, path.p + path.len - 20, 20);
  return true;
}

static bool decode_v3(Span in, bool exact_in, UroStep* st) {
  Span path;
  uint8_t first[20], last[20];
  if (!address_at(in, 0, st->recipient) || !u256_at(in, 32, st->amount) ||
      !u256_at(in, 64, st->limit) || !bytes_at(in, 96, &path) ||
      !bool_at(in, 128, &st->payer_is_user) ||
      !v3_path_ends(path, first, last)) {
    return false;
  }
  /* Exact-output paths are encoded output-first. */
  memcpy(st->token_in, exact_in ? first : last, 20);
  memcpy(st->token_out, exact_in ? last : first, 20);
  st->kind = exact_in ? URO_V3_SWAP_EXACT_IN : URO_V3_SWAP_EXACT_OUT;
  return true;
}

static bool decode_v2(Span in, bool exact_in, UroStep* st) {
  uint64_t off, n;
  if (!address_at(in, 0, st->recipient) || !u256_at(in, 32, st->amount) ||
      !u256_at(in, 64, st->limit) || !uint_at(in, 96, 4, &off) ||
      !bool_at(in, 128, &st->payer_is_user) ||
      !uint_at(in, (size_t)off, 4, &n) || n < 2 || n > 8) {
    return false;
  }
  uint8_t ignored[20];
  for (uint64_t i = 0; i < n; i++) {
    uint8_t* dst = i == 0 ? st->token_in : (i == n - 1 ? st->token_out : ignored);
    if (!address_at(in, (size_t)off + 32 + 32 * (size_t)i, dst)) return false;
  }
  st->kind = exact_in ? URO_V2_SWAP_EXACT_IN : URO_V2_SWAP_EXACT_OUT;
  return true;
}

/* PermitSingle{details{token, amount, expiration, nonce}, spender,
 * sigDeadline} then bytes signature. */
static bool decode_permit(Span in, UroStep* st) {
  uint64_t nonce;
  uint8_t sig_deadline[32];
  Span sig;
  if (!address_at(in, 0, st->token_in) || !u160_at(in, 32, st->amount) ||
      !uint_at(in, 64, 6, &st->expiration) || !uint_at(in, 96, 6, &nonce) ||
      !address_at(in, 128, st->token_out) || !u256_at(in, 160, sig_deadline) ||
      !bytes_at(in, 192, &sig)) {
    return false;
  }
  st->kind = URO_PERMIT2_PERMIT;
  return true;
}

static bool decode_step(uint8_t cmd, Span in, UroStep* st) {
  memset(st, 0, sizeof(*st));
  switch (cmd) {
    case CMD_V3_SWAP_EXACT_IN:
      return decode_v3(in, true, st);
    case CMD_V3_SWAP_EXACT_OUT:
      return decode_v3(in, false, st);
    case CMD_V2_SWAP_EXACT_IN:
      return decode_v2(in, true, st);
    case CMD_V2_SWAP_EXACT_OUT:
      return decode_v2(in, false, st);
    case CMD_PERMIT2_PERMIT:
      return decode_permit(in, st);
    case CMD_WRAP_ETH:
    case CMD_UNWRAP_WETH:
      st->kind = cmd == CMD_WRAP_ETH ? URO_WRAP_ETH : URO_UNWRAP_WETH;
      return address_at(in, 0, st->recipient) && u256_at(in, 32, st->amount);
    case CMD_SWEEP:
    case CMD_PAY_PORTION:
    case CMD_TRANSFER:
      st->kind = cmd == CMD_SWEEP          ? URO_SWEEP
                 : cmd == CMD_PAY_PORTION ? URO_PAY_PORTION
                                          : URO_TRANSFER;
      return address_at(in, 0, st->token_in) &&
             address_at(in, 32, st->recipient) && u256_at(in, 64, st->amount);
    default:
      return false;
  }
}

bool ur_oracle_decode(const uint8_t* calldata, size_t len, UroPlan* out) {
  static const uint8_t SEL_DEADLINE[4] = {0x35, 0x93, 0x56, 0x4c};
  static const uint8_t SEL_NO_DEADLINE[4] = {0x24, 0x85, 0x6b, 0xc3};
  memset(out, 0, sizeof(*out));
  if (!calldata || len < 4) return false;
  if (memcmp(calldata, SEL_DEADLINE, 4) == 0) {
    out->has_deadline = true;
  } else if (memcmp(calldata, SEL_NO_DEADLINE, 4) != 0) {
    return false;
  }
  Span body = {calldata + 4, len - 4};
  Span cmds;
  uint64_t inputs_off, n;
  if (!bytes_at(body, 0, &cmds) || !uint_at(body, 32, 4, &inputs_off) ||
      (out->has_deadline && !uint_at(body, 64, 8, &out->deadline)) ||
      !uint_at(body, (size_t)inputs_off, 4, &n)) {
    return false;
  }
  if (cmds.len == 0 || cmds.len > URO_MAX_STEPS || n != cmds.len) return false;
  /* bytes[] element heads are relative to the first head word. */
  Span heads;
  size_t heads_start = (size_t)inputs_off + 32;
  if (heads_start > body.len) return false;
  heads.p = body.p + heads_start;
  heads.len = body.len - heads_start;
  for (size_t i = 0; i < cmds.len; i++) {
    const uint8_t cmd = cmds.p[i];
    Span in;
    if ((cmd & CMD_FLAGS) != 0 || !bytes_at(heads, 32 * i, &in) ||
        !decode_step(cmd, in, &out->steps[i])) {
      memset(out, 0, sizeof(*out));
      return false;
    }
  }
  out->n = (uint8_t)cmds.len;
  return true;
}

static bool ur_recipient_is_constant(const uint8_t recipient[20], uint8_t which) {
  for (int i = 0; i < 19; i++) {
    if (recipient[i] != 0) return false;
  }
  return recipient[19] == which;
}

/* ActionConstants.CONTRACT_BALANCE: "everything the router holds". */
static bool is_contract_balance(const uint8_t a[32]) {
  if (a[0] != 0x80) return false;
  for (int i = 1; i < 32; i++) {
    if (a[i] != 0) return false;
  }
  return true;
}

static bool is_zero32(const uint8_t a[32]) {
  for (int i = 0; i < 32; i++) {
    if (a[i] != 0) return false;
  }
  return true;
}

/* The router itself, by placeholder or by its own address: either way it
 * holds the funds for a later step. Apps encode both. */
static bool is_router(const uint8_t r[20], const uint8_t router[20]) {
  return ur_recipient_is_constant(r, URO_RECIPIENT_ADDRESS_THIS) ||
         memcmp(r, router, 20) == 0;
}

/* a += b, big-endian; false on overflow. */
static bool add32(uint8_t a[32], const uint8_t b[32]) {
  unsigned carry = 0;
  for (int i = 31; i >= 0; i--) {
    carry += (unsigned)a[i] + b[i];
    a[i] = (uint8_t)carry;
    carry >>= 8;
  }
  return carry == 0;
}

static bool is_swap(UroKind k) {
  return k == URO_V3_SWAP_EXACT_IN || k == URO_V3_SWAP_EXACT_OUT ||
         k == URO_V2_SWAP_EXACT_IN || k == URO_V2_SWAP_EXACT_OUT;
}

bool ur_oracle_summarize(const UroPlan* plan, const uint8_t router[20],
                         const uint8_t value[32], UroSummary* out) {
  memset(out, 0, sizeof(*out));
  if (!plan || plan->n == 0) return false;
  size_t i = 0;
  const UroStep* permit = NULL;
  const UroStep* wrap = NULL;
  /* Before the swap: at most one permit or one wrap. */
  if (i < plan->n && plan->steps[i].kind == URO_PERMIT2_PERMIT) {
    permit = &plan->steps[i++];
  } else if (i < plan->n && plan->steps[i].kind == URO_WRAP_ETH) {
    wrap = &plan->steps[i++];
  }
  if (i >= plan->n || !is_swap(plan->steps[i].kind)) return false;
  const UroStep* swap = &plan->steps[i++];
  /* A split route: a second exact-in swap of the same pair, paid and
   * delivered the same way. Its totals are what the user spends and is
   * guaranteed (each swap enforces its own minimum). */
  UroStep split;
  if (i < plan->n && is_swap(plan->steps[i].kind)) {
    const UroStep* b = &plan->steps[i++];
    const bool in_a = swap->kind == URO_V3_SWAP_EXACT_IN ||
                      swap->kind == URO_V2_SWAP_EXACT_IN;
    const bool in_b =
        b->kind == URO_V3_SWAP_EXACT_IN || b->kind == URO_V2_SWAP_EXACT_IN;
    split = *swap;
    if (!in_a || !in_b || memcmp(b->token_in, swap->token_in, 20) != 0 ||
        memcmp(b->token_out, swap->token_out, 20) != 0 ||
        memcmp(b->recipient, swap->recipient, 20) != 0 ||
        b->payer_is_user != swap->payer_is_user ||
        is_contract_balance(swap->amount) || is_contract_balance(b->amount) ||
        !add32(split.amount, b->amount) || !add32(split.limit, b->limit)) {
      return false;
    }
    swap = &split;
  }
  const UroStep* fee = NULL;
  const UroStep* tail[2] = {NULL, NULL}; /* final, then clean-up */
  if (i < plan->n && plan->steps[i].kind == URO_PAY_PORTION) {
    fee = &plan->steps[i++];
  }
  for (int t = 0; t < 2 && i < plan->n &&
                  (plan->steps[i].kind == URO_SWEEP ||
                   plan->steps[i].kind == URO_UNWRAP_WETH);
       t++) {
    tail[t] = &plan->steps[i++];
  }
  if (i != plan->n) return false;
  const UroStep* final = tail[0];
  const UroStep* cleanup = tail[1];

  out->exact_in = swap->kind == URO_V3_SWAP_EXACT_IN ||
                  swap->kind == URO_V2_SWAP_EXACT_IN;
  memcpy(out->token_in, swap->token_in, 20);
  memcpy(out->token_out, swap->token_out, 20);

  /* Input side. */
  if (wrap) {
    /* ETH in: the router wraps msg.value and pays from its own balance.
     * Exact in spends all of it; exact out spends at most its limit, which
     * may not exceed what was sent (the rest is refunded, below). */
    if (swap->payer_is_user || is_zero32(value) ||
        !is_router(wrap->recipient, router) ||
        (memcmp(wrap->amount, value, 32) != 0 &&
         !is_contract_balance(wrap->amount)) ||
        (out->exact_in && memcmp(swap->amount, value, 32) != 0 &&
         !is_contract_balance(swap->amount)) ||
        (!out->exact_in && memcmp(swap->limit, value, 32) > 0)) {
      return false;
    }
    out->in_is_eth = true;
    memcpy(out->amount_in, value, 32);
  } else {
    /* Token in, pulled from the user through Permit2. */
    if (!is_zero32(value) || !swap->payer_is_user ||
        is_contract_balance(swap->amount)) {
      return false;
    }
    memcpy(out->amount_in, out->exact_in ? swap->amount : swap->limit, 32);
  }
  if (permit) {
    if (memcmp(permit->token_out /* spender */, router, 20) != 0 ||
        memcmp(permit->token_in, swap->token_in, 20) != 0) {
      return false;
    }
    out->has_permit = true;
    memcpy(out->permit_token, permit->token_in, 20);
    memcpy(out->permit_amount, permit->amount, 32);
    out->permit_expiration = permit->expiration;
  }

  /* Output side. */
  memcpy(out->amount_out, out->exact_in ? swap->limit : swap->amount, 32);
  const UroStep* deliver = swap;
  if (!is_router(swap->recipient, router)) {
    /* Delivered by the swap itself: what follows is clean-up. */
    if (fee || cleanup) return false;
    cleanup = final;
    goto delivered;
  }
  /* Held by the router: a final step must deliver it, after any fee. */
  if (!final || is_contract_balance(final->amount)) return false;
  if (final->kind == URO_SWEEP &&
      memcmp(final->token_in, swap->token_out, 20) != 0) {
    return false;
  }
  if (fee) {
    uint64_t bips = 0;
    for (int k = 24; k < 32; k++) bips = (bips << 8) | fee->amount[k];
    for (int k = 0; k < 24; k++) {
      if (fee->amount[k] != 0) return false;
    }
    if (bips == 0 || bips > 10000 ||
        memcmp(fee->token_in, swap->token_out, 20) != 0 ||
        is_router(fee->recipient, router)) {
      return false;
    }
    out->has_fee = true;
    out->fee_bips = (uint16_t)bips;
    memcpy(out->fee_recipient, fee->recipient, 20);
    /* The user's floor is what the final step guarantees after the fee. */
    if (out->exact_in) memcpy(out->amount_out, final->amount, 32);
  }
  if (is_router(final->recipient, router)) {
    return false;
  }
  /* Apps put the floor on the final step and leave the swap's limit at 0:
   * the user is guaranteed the larger of the two. */
  if (out->exact_in && !fee &&
      memcmp(final->amount, out->amount_out, 32) > 0) {
    memcpy(out->amount_out, final->amount, 32);
  }
  out->out_is_eth = final->kind == URO_UNWRAP_WETH;
  deliver = final;
delivered:
  /* Apps add one clean-up step returning leftover ETH (unwrapped, or swept
   * as address 0). Allowed only to the recipient the review names. */
  if (cleanup && (memcmp(cleanup->recipient, deliver->recipient, 20) != 0 ||
                  (cleanup->kind == URO_SWEEP &&
                   !ur_recipient_is_constant(cleanup->token_in, 0)))) {
    return false;
  }
  out->recipient_is_sender =
      ur_recipient_is_constant(deliver->recipient, URO_RECIPIENT_MSG_SENDER);
  memcpy(out->recipient, deliver->recipient, 20);
  return true;
}
