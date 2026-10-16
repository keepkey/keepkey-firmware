/*
 * This file is part of the KeepKey project.
 *
 * Uniswap Universal Router execute() decoder, fed the calldata as it arrives.
 * Offsets are followed as Solidity's abi.decode (and the router's
 * CalldataDecoder) follows them, so the device reads the same values the
 * contract executes; they must point forward (uniswap_ur.h). Anything outside
 * the supported command set, a set allow-revert flag, or a value wider than
 * its declared type rejects the whole call.
 */

#include "keepkey/firmware/uniswap_ur.h"

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
#define CMD_V4_SWAP 0x10
/* Bit 7 is FLAG_ALLOW_REVERT; bit 6 is unused. Either set: not decoded. */
#define CMD_FLAGS 0xc0

#define V3_HOP 23 /* fee(3) + token(20) */

/* v4-periphery Actions.sol (the version UR 2.1.2 on Base was built with) */
#define ACT_SWAP_EXACT_IN 0x07
#define ACT_SWAP_EXACT_OUT 0x09
#define ACT_SETTLE 0x0b
#define ACT_TAKE 0x0e
#define ACT_TAKE_PORTION 0x10

enum {
  S_SELECTOR,
  S_HEAD, /* execute()'s head words */
  S_CMDS_LEN,
  S_CMDS, /* the command bytes, one at a time */
  S_INPUTS_LEN,
  S_INPUT_HEAD, /* bytes[] element offsets */
  S_ELEM_LEN,
  S_FIELD,   /* an input's head words */
  S_DYN_LEN, /* an input's dynamic tail: its length word */
  S_V3_PATH, /* path bytes, one at a time */
  S_V2_PATH, /* path addresses */
  /* V4_SWAP: (bytes actions, bytes[] params) inside the input. */
  S4_HEAD,
  S4_ACTS_LEN,
  S4_ACTS, /* action bytes, one at a time */
  S4_PARAMS_LEN,
  S4_PARAM_HEAD,
  S4_PARAM_LEN,
  S4_ARGS,     /* SETTLE / TAKE / TAKE_PORTION: three words */
  S4_SW_OFF,   /* swap params: the struct's offset */
  S4_SW_HEAD,  /* Exact{In,Out}putParams head words */
  S4_PATH_LEN, /* PathKey[] */
  S4_PATH_HEAD,
  S4_PK,          /* PathKey head words */
  S4_PK_HOOKDATA, /* its hookData length: must be 0 */
  S_DONE,
};

/* An input head word: what it holds (high nibble) and where it goes. */
enum {
  F_ADDR = 0x10,
  F_U256 = 0x20,
  F_U160 = 0x30,
  F_U48 = 0x40,
  F_BOOL = 0x50,
  F_OFF = 0x60
};
enum {
  D_NONE,
  D_TOKEN_IN,
  D_TOKEN_OUT,
  D_RECIPIENT,
  D_AMOUNT,
  D_LIMIT,
  D_EXPIRATION,
  D_PAYER
};

/* (recipient, amount, limit, path, payerIsUser): a V3 path is bytes, a V2
 * path address[]. Later routers append a further dynamic argument, which is
 * not read, as abi.decode does not read it for the older shape. */
static const uint8_t SWAP_FIELDS[] = {F_ADDR | D_RECIPIENT, F_U256 | D_AMOUNT,
                                      F_U256 | D_LIMIT, F_OFF,
                                      F_BOOL | D_PAYER};
/* PermitSingle{details{token, amount, expiration, nonce}, spender,
 * sigDeadline} then bytes signature. */
static const uint8_t PERMIT_FIELDS[] = {F_ADDR | D_TOKEN_IN,
                                        F_U160 | D_AMOUNT,
                                        F_U48 | D_EXPIRATION,
                                        F_U48,
                                        F_ADDR | D_TOKEN_OUT,
                                        F_U256,
                                        F_OFF};
static const uint8_t WRAP_FIELDS[] = {F_ADDR | D_RECIPIENT, F_U256 | D_AMOUNT};
static const uint8_t SWEEP_FIELDS[] = {F_ADDR | D_TOKEN_IN,
                                       F_ADDR | D_RECIPIENT, F_U256 | D_AMOUNT};

typedef struct {
  uint8_t cmd;
  uint8_t kind;
  uint8_t nfields;
  const uint8_t* fields;
} Command;

static const Command COMMANDS[] = {
    {CMD_V3_SWAP_EXACT_IN, UR_V3_SWAP_EXACT_IN, 5, SWAP_FIELDS},
    {CMD_V3_SWAP_EXACT_OUT, UR_V3_SWAP_EXACT_OUT, 5, SWAP_FIELDS},
    {CMD_V2_SWAP_EXACT_IN, UR_V2_SWAP_EXACT_IN, 5, SWAP_FIELDS},
    {CMD_V2_SWAP_EXACT_OUT, UR_V2_SWAP_EXACT_OUT, 5, SWAP_FIELDS},
    {CMD_PERMIT2_PERMIT, UR_PERMIT2_PERMIT, 7, PERMIT_FIELDS},
    {CMD_WRAP_ETH, UR_WRAP_ETH, 2, WRAP_FIELDS},
    {CMD_UNWRAP_WETH, UR_UNWRAP_WETH, 2, WRAP_FIELDS},
    {CMD_SWEEP, UR_SWEEP, 3, SWEEP_FIELDS},
    {CMD_PAY_PORTION, UR_PAY_PORTION, 3, SWEEP_FIELDS},
    {CMD_TRANSFER, UR_TRANSFER, 3, SWEEP_FIELDS},
    /* Parsed by the S4_ states; the kind is set from its actions. */
    {CMD_V4_SWAP, UR_V4_SWAP_EXACT_IN, 0, NULL},
};

static const Command* command(uint8_t cmd) {
  for (size_t i = 0; i < sizeof(COMMANDS) / sizeof(COMMANDS[0]); i++) {
    if (COMMANDS[i].cmd == cmd) return &COMMANDS[i];
  }
  return NULL;
}

static bool fail(UrStream* s) {
  s->failed = true;
  return false;
}

/* The word's top 32 - `bytes` bytes are zero. Offsets and lengths use 4:
 * size_t is 32-bit on the device, so a wider value would wrap there while a
 * 64-bit host (and the router) read it in full. */
static bool narrow(const uint8_t w[32], size_t bytes, uint64_t* out) {
  uint64_t v = 0;
  for (size_t i = 0; i < 32; i++) {
    if (i < 32 - bytes && w[i] != 0) return false;
    v = (v << 8) | w[i];
  }
  if (out) *out = v;
  return true;
}

static bool word_u32(UrStream* s, uint32_t* out) {
  uint64_t v;
  if (!narrow(s->word, 4, &v)) return fail(s);
  *out = (uint32_t)v;
  return true;
}

/* The next field starts at `at`: never behind what was already read, never
 * past the end of the call. */
static bool next_at(UrStream* s, uint64_t at) {
  if (at < s->pos || at > s->total) return fail(s);
  s->at = (uint32_t)at;
  return true;
}

/* The next word of the current input, at `rel` into its payload: it must lie
 * inside the payload. */
static bool next_in_input(UrStream* s, uint64_t rel) {
  if (rel > s->len || s->len - rel < 32) return fail(s);
  return next_at(s, (uint64_t)s->base + rel);
}

static const Command* current(const UrStream* s) {
  return command(s->cmds[s->step]);
}

static UrStep* current_step(const UrStream* s) {
  return &s->plan->steps[s->pstep];
}

/* A fresh plan step for the current input (a V4 fee takes the next one). */
static UrStep* add_step(UrStream* s) {
  if (s->nsteps >= UR_MAX_STEPS) {
    fail(s);
    return NULL;
  }
  UrStep* st = &s->plan->steps[s->nsteps++];
  memset(st, 0, sizeof(*st));
  return st;
}

static bool next_input(UrStream* s) {
  if (s->step == s->ncmds) {
    s->state = S_DONE;
    return true;
  }
  s->state = S_ELEM_LEN;
  return next_at(s, (uint64_t)s->heads + s->elem[s->step]);
}

/* The input in hand is complete; the next one starts at or past its end. */
static bool input_done(UrStream* s) {
  const uint32_t end = s->base + s->len; /* <= total, checked at its length */
  s->step++;
  if (s->step < s->ncmds && (uint64_t)s->heads + s->elem[s->step] < end) {
    return fail(s);
  }
  return next_input(s);
}

static bool head_field(UrStream* s) {
  const Command* c = current(s);
  UrStep* st = current_step(s);
  const uint8_t f = c->fields[s->field];
  uint8_t* dst = NULL;
  switch (f & 0x0f) {
    case D_TOKEN_IN:
      dst = st->token_in;
      break;
    case D_TOKEN_OUT:
      dst = st->token_out;
      break;
    case D_RECIPIENT:
      dst = st->recipient;
      break;
    case D_AMOUNT:
      dst = st->amount;
      break;
    case D_LIMIT:
      dst = st->limit;
      break;
    default:
      break;
  }
  uint64_t v = 0;
  switch (f & 0xf0) {
    case F_ADDR:
      if (!narrow(s->word, 20, NULL)) return fail(s);
      if (dst) memcpy(dst, s->word + 12, 20);
      break;
    case F_U160:
      if (!narrow(s->word, 20, NULL)) return fail(s);
      /* fall through */
    case F_U256:
      if (dst) memcpy(dst, s->word, 32);
      break;
    case F_U48:
      if (!narrow(s->word, 6, &v)) return fail(s);
      if ((f & 0x0f) == D_EXPIRATION) st->expiration = v;
      break;
    case F_BOOL:
      if (!narrow(s->word, 1, &v) || v > 1) return fail(s);
      st->payer_is_user = v == 1;
      break;
    default: /* F_OFF: the dynamic tail, relative to the payload */
      if (!narrow(s->word, 4, &v)) return fail(s);
      s->n = (uint32_t)v;
      break;
  }
  s->field++;
  if (s->field < c->nfields) return next_in_input(s, 32u * s->field);
  bool tail = false;
  for (uint8_t i = 0; i < c->nfields; i++) tail = tail || c->fields[i] == F_OFF;
  if (!tail) return input_done(s); /* static input */
  s->state = S_DYN_LEN;
  return next_in_input(s, s->n);
}

/* The dynamic tail's length word: a V3 path, a V2 path, or the permit's
 * signature (whose bytes are not read). */
static bool dyn_len(UrStream* s) {
  const uint8_t kind = current(s)->kind;
  uint32_t n;
  if (!word_u32(s, &n)) return false;
  /* The payload starts right after this word. */
  const uint32_t start = s->pos - s->base;
  if (kind == UR_V2_SWAP_EXACT_IN || kind == UR_V2_SWAP_EXACT_OUT) {
    if (n < 2 || n > 8) return fail(s);
    s->n = n;
    s->k = 0;
    s->state = S_V2_PATH;
    return next_in_input(s, start);
  }
  if (n > s->len - start) return fail(s);
  if (kind == UR_PERMIT2_PERMIT) return input_done(s);
  /* V3 path: token(20) (fee(3) token(20))+ — at least one hop. */
  if (n < 20 + V3_HOP || (n - 20) % V3_HOP != 0) return fail(s);
  s->n = n;
  s->k = 0;
  s->state = S_V3_PATH;
  return next_at(s, s->pos);
}

static bool v3_path_byte(UrStream* s, uint8_t b) {
  UrStep* st = current_step(s);
  /* Exact-output paths are encoded output-first. */
  const bool exact_in = st->kind == UR_V3_SWAP_EXACT_IN;
  if (s->k < 20) (exact_in ? st->token_in : st->token_out)[s->k] = b;
  if (s->k >= s->n - 20) {
    (exact_in ? st->token_out : st->token_in)[s->k - (s->n - 20)] = b;
  }
  if (++s->k == s->n) return input_done(s);
  return next_at(s, s->pos);
}

static bool v2_path_word(UrStream* s) {
  UrStep* st = current_step(s);
  if (!narrow(s->word, 20, NULL)) return fail(s);
  if (s->k == 0) memcpy(st->token_in, s->word + 12, 20);
  if (s->k == s->n - 1) memcpy(st->token_out, s->word + 12, 20);
  if (++s->k == s->n) return input_done(s);
  return next_in_input(s, s->pos - s->base);
}

/* ---- V4_SWAP -------------------------------------------------------------
 * The input is abi.encode(bytes actions, bytes[] params) for the router's
 * V4Router (v4-periphery as built into UR 2.1.2). Accepted action lists:
 *   SWAP_EXACT_IN|SWAP_EXACT_OUT, SETTLE, [TAKE_PORTION,] TAKE
 *   SETTLE, SWAP_EXACT_IN, [TAKE_PORTION,] TAKE
 * which the router resolves completely (PoolManager reverts on any open
 * delta), so they read as one swap: what SETTLE pays, what the swap
 * guarantees, where TAKE sends it. Anything else is refused. */

static bool is_zero(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (p[i] != 0) return false;
  }
  return true;
}

/* ActionConstants.CONTRACT_BALANCE (1 << 255). */
static bool is_balance_word(const uint8_t w[32]) {
  return w[0] == 0x80 && is_zero(w + 1, 31);
}

/* int24, sign-extended. */
static bool narrow_int24(const uint8_t w[32]) {
  const uint8_t pad = (w[29] & 0x80) ? 0xff : 0x00;
  for (int i = 0; i < 29; i++) {
    if (w[i] != pad) return false;
  }
  return true;
}

static bool v4_swap_action(uint8_t a) {
  return a == ACT_SWAP_EXACT_IN || a == ACT_SWAP_EXACT_OUT;
}

/* The next word of the current param, at `rel` into its payload. */
static bool next_in_param(UrStream* s, uint64_t rel) {
  if (rel > s->v4.len || s->v4.len - rel < 32) return fail(s);
  return next_at(s, (uint64_t)s->v4.base + rel);
}

static bool v4_param_start(UrStream* s) {
  const uint64_t at = (uint64_t)s->v4.heads + s->v4.elem[s->v4.act];
  /* Params in index order, none starting inside the previous one. */
  if (s->v4.act > 0 && at < (uint64_t)s->v4.base + s->v4.len) return fail(s);
  if (at < s->base) return fail(s);
  s->state = S4_PARAM_LEN;
  return next_in_input(s, at - s->base);
}

static bool v4_done(UrStream* s) {
  UrStep* st = current_step(s);
  /* SETTLE pays the swap's input, TAKE takes its output. */
  if (memcmp(s->v4.settle_cur, st->token_in, 20) != 0 ||
      memcmp(s->v4.take_cur, st->token_out, 20) != 0 ||
      memcmp(st->token_in, st->token_out, 20) == 0) {
    return fail(s);
  }
  if (s->nsteps > s->pstep + 1) {
    const UrStep* fee = &s->plan->steps[s->pstep + 1];
    if (memcmp(fee->token_in, st->token_out, 20) != 0) return fail(s);
  }
  /* Native ETH is settled from the router's balance (msg.value), whatever
   * the payer flag says (DeltaResolver._settle). */
  if (is_zero(st->token_in, 20)) st->payer_is_user = false;
  return input_done(s);
}

static bool v4_param_done(UrStream* s) {
  if (++s->v4.act < s->v4.nacts) return v4_param_start(s);
  return v4_done(s);
}

static bool v4_action_byte(UrStream* s, uint8_t b) {
  s->v4.acts[s->k++] = b;
  if (s->k < s->v4.nacts) return next_at(s, s->pos);
  const uint8_t* a = s->v4.acts;
  const uint8_t n = s->v4.nacts;
  const bool swap_first = v4_swap_action(a[0]) && a[1] == ACT_SETTLE;
  const bool settle_first = a[0] == ACT_SETTLE && a[1] == ACT_SWAP_EXACT_IN;
  const bool portion = n == 4 && a[2] == ACT_TAKE_PORTION;
  if (!(swap_first || settle_first) || a[n - 1] != ACT_TAKE ||
      (n != 3 && !portion) || (portion && a[0] == ACT_SWAP_EXACT_OUT)) {
    return fail(s);
  }
  UrStep* st = current_step(s);
  st->kind =
      (a[0] == ACT_SWAP_EXACT_OUT) ? UR_V4_SWAP_EXACT_OUT : UR_V4_SWAP_EXACT_IN;
  if (portion) {
    UrStep* fee = add_step(s);
    if (!fee) return false;
    fee->kind = UR_V4_TAKE_PORTION;
  }
  s->state = S4_PARAMS_LEN;
  return next_in_input(s, s->v4.heads); /* the params offset, for now */
}

/* SETTLE (currency, amount, payerIsUser), TAKE (currency, recipient,
 * amount), TAKE_PORTION (currency, recipient, bips). */
static bool v4_arg(UrStream* s) {
  UrStep* st = current_step(s);
  const uint8_t a = s->v4.acts[s->v4.act];
  /* TAKE_PORTION's own step, allocated with the action list. */
  UrStep* fee = a == ACT_TAKE_PORTION ? &s->plan->steps[s->pstep + 1] : NULL;
  const uint8_t* w = s->word;
  uint64_t v = 0;
  if (s->field == 0 || (s->field == 1 && a != ACT_SETTLE)) {
    if (!narrow(w, 20, NULL)) return fail(s);
  }
  switch (s->field) {
    case 0:
      memcpy(a == ACT_SETTLE ? s->v4.settle_cur
             : a == ACT_TAKE ? s->v4.take_cur
                             : fee->token_in,
             w + 12, 20);
      break;
    case 1:
      if (a == ACT_TAKE) {
        memcpy(st->recipient, w + 12, 20);
      } else if (a == ACT_TAKE_PORTION) {
        memcpy(fee->recipient, w + 12, 20);
      } else if (!s->v4.swap_done) {
        /* SETTLE first pays what the swap then spends (OPEN_DELTA): an
         * amount, or the router's whole balance. Nothing owed yet, so
         * OPEN_DELTA here would pay nothing. */
        if (is_zero(w, 32)) return fail(s);
        memcpy(st->amount, w, 32);
      } else if (!is_zero(w, 32)) {
        /* After the swap only OPEN_DELTA: exactly the debt. */
        return fail(s);
      }
      break;
    default:
      if (a == ACT_SETTLE) {
        if (!narrow(w, 1, &v) || v > 1) return fail(s);
        st->payer_is_user = v == 1;
        /* The user paying the router's own balance: refused. */
        if (!s->v4.swap_done && st->payer_is_user &&
            is_balance_word(st->amount)) {
          return fail(s);
        }
      } else if (a == ACT_TAKE_PORTION) {
        memcpy(fee->amount, w, 32);
      } else if (!is_zero(w, 32) && (st->kind != UR_V4_SWAP_EXACT_OUT ||
                                     memcmp(w, st->amount, 32) != 0)) {
        /* TAKE: the whole credit (OPEN_DELTA), or exactly an exact-output
         * swap's amount. */
        return fail(s);
      }
      break;
  }
  if (++s->field < 3) return next_in_param(s, 32u * s->field);
  return v4_param_done(s);
}

/* Exact{In,Out}putParams: (currency, PathKey[] path, uint256[]
 * minHopPriceX36, uint128 amount, uint128 limit). minHopPriceX36 only adds
 * revert conditions and is not read. */
static bool v4_swap_head(UrStream* s) {
  UrStep* st = current_step(s);
  const bool exact_in = st->kind == UR_V4_SWAP_EXACT_IN;
  const uint8_t* w = s->word;
  uint64_t v = 0;
  switch (s->field) {
    case 0:
      if (!narrow(w, 20, NULL)) return fail(s);
      memcpy(exact_in ? st->token_in : st->token_out, w + 12, 20);
      break;
    case 1:
      if (!narrow(w, 4, &v)) return fail(s);
      s->v4.path = (uint32_t)v; /* relative to the struct, for now */
      break;
    case 2:
      if (!narrow(w, 4, NULL)) return fail(s);
      break;
    case 3:
      if (!narrow(w, 16, NULL)) return fail(s);
      if (exact_in && s->v4.acts[0] == ACT_SETTLE) {
        /* Spends what SETTLE paid in: must be OPEN_DELTA. */
        if (!is_zero(w, 32)) return fail(s);
      } else {
        if (is_zero(w, 32)) return fail(s);
        memcpy(st->amount, w, 32);
      }
      break;
    default:
      if (!narrow(w, 16, NULL)) return fail(s);
      memcpy(st->limit, w, 32);
      s->state = S4_PATH_LEN;
      return next_in_param(s, (uint64_t)s->v4.sw + s->v4.path);
  }
  s->field++;
  return next_in_param(s, (uint64_t)s->v4.sw + 32u * s->field);
}

static bool v4_pathkey_start(UrStream* s) {
  const uint64_t at = (uint64_t)s->v4.path + s->v4.pk[s->k];
  if (at < s->v4.base) return fail(s);
  s->v4.pkb = (uint32_t)(at - s->v4.base);
  s->field = 0;
  s->state = S4_PK;
  return next_in_param(s, s->v4.pkb);
}

static bool add_hook(UrStream* s, const uint8_t h[20]) {
  UrPlan* p = s->plan;
  for (uint8_t i = 0; i < p->n_hooks; i++) {
    if (memcmp(p->hooks[i], h, 20) == 0) return true;
  }
  if (p->n_hooks >= UR_MAX_HOOKS) return fail(s);
  memcpy(p->hooks[p->n_hooks++], h, 20);
  return true;
}

/* PathKey (intermediateCurrency, uint24 fee, int24 tickSpacing, hooks,
 * bytes hookData). Exact input walks currencyIn -> path[0] -> ... ->
 * path[n-1] (the output); exact output walks back from currencyOut, so
 * path[0] is the input. */
static bool v4_pathkey(UrStream* s) {
  UrStep* st = current_step(s);
  const uint8_t* w = s->word;
  uint64_t v = 0;
  switch (s->field) {
    case 0:
      if (!narrow(w, 20, NULL)) return fail(s);
      if (st->kind == UR_V4_SWAP_EXACT_IN) {
        memcpy(st->token_out, w + 12, 20);
      } else if (s->k == 0) {
        memcpy(st->token_in, w + 12, 20);
      }
      break;
    case 1:
      if (!narrow(w, 3, NULL)) return fail(s);
      break;
    case 2:
      if (!narrow_int24(w)) return fail(s);
      break;
    case 3:
      if (!narrow(w, 20, NULL)) return fail(s);
      if (!is_zero(w + 12, 20) && !add_hook(s, w + 12)) return false;
      break;
    default:
      if (!narrow(w, 4, &v)) return fail(s);
      s->state = S4_PK_HOOKDATA;
      return next_in_param(s, (uint64_t)s->v4.pkb + v);
  }
  s->field++;
  return next_in_param(s, (uint64_t)s->v4.pkb + 32u * s->field);
}

static bool v4_word(UrStream* s) {
  uint32_t v;
  switch (s->state) {
    case S4_HEAD:
      /* actions offset, params offset: relative to the input. */
      if (!word_u32(s, s->field == 0 ? &s->n : &s->v4.heads)) return false;
      if (++s->field < 2) return next_in_input(s, 32);
      s->state = S4_ACTS_LEN;
      return next_in_input(s, s->n);
    case S4_ACTS_LEN:
      if (!word_u32(s, &v)) return false;
      if (v < 3 || v > 4) return fail(s);
      s->v4.nacts = (uint8_t)v;
      s->k = 0;
      s->state = S4_ACTS;
      return next_at(s, s->pos);
    case S4_PARAMS_LEN:
      if (!word_u32(s, &v)) return false;
      if (v != s->v4.nacts) return fail(s);
      s->v4.heads = s->pos;
      s->k = 0;
      s->state = S4_PARAM_HEAD;
      return next_at(s, s->pos);
    case S4_PARAM_HEAD:
      if (!word_u32(s, &s->v4.elem[s->k])) return false;
      if (++s->k < s->v4.nacts) return next_at(s, s->pos);
      s->v4.act = 0;
      return v4_param_start(s);
    case S4_PARAM_LEN:
      if (!word_u32(s, &s->v4.len)) return false;
      if (s->v4.len > s->base + s->len - s->pos) return fail(s);
      s->v4.base = s->pos;
      s->field = 0;
      s->state = v4_swap_action(s->v4.acts[s->v4.act]) ? S4_SW_OFF : S4_ARGS;
      return next_in_param(s, 0);
    case S4_ARGS:
      return v4_arg(s);
    case S4_SW_OFF:
      if (!word_u32(s, &s->v4.sw)) return false;
      s->state = S4_SW_HEAD;
      return next_in_param(s, s->v4.sw);
    case S4_SW_HEAD:
      return v4_swap_head(s);
    case S4_PATH_LEN:
      if (!word_u32(s, &v)) return false;
      if (v == 0 || v > UR_V4_MAX_PATH) return fail(s);
      s->v4.npath = (uint8_t)v;
      s->v4.path = s->pos;
      s->k = 0;
      s->state = S4_PATH_HEAD;
      return next_at(s, s->pos);
    case S4_PATH_HEAD:
      if (!word_u32(s, &s->v4.pk[s->k])) return false;
      if (++s->k < s->v4.npath) return next_at(s, s->pos);
      s->k = 0;
      return v4_pathkey_start(s);
    case S4_PK:
      return v4_pathkey(s);
    case S4_PK_HOOKDATA:
      /* hookData is opaque input to a third-party contract: none is
       * accepted (none in the D-021 sample). */
      if (!is_zero(s->word, 32)) return fail(s);
      if (++s->k < s->v4.npath) return v4_pathkey_start(s);
      s->v4.swap_done = true;
      return v4_param_done(s);
    default:
      return fail(s);
  }
}

static bool on_byte(UrStream* s, uint8_t b) {
  if (s->state == S_CMDS) {
    if ((b & CMD_FLAGS) != 0 || !command(b)) return fail(s);
    s->cmds[s->k++] = b;
    if (s->k < s->ncmds) return next_at(s, s->pos);
    s->state = S_INPUTS_LEN;
    return next_at(s, (uint64_t)4 + s->heads);
  }
  if (s->state == S4_ACTS) return v4_action_byte(s, b);
  return v3_path_byte(s, b);
}

static bool on_word(UrStream* s) {
  static const uint8_t SEL_DEADLINE[4] = {0x35, 0x93, 0x56, 0x4c};
  static const uint8_t SEL_NO_DEADLINE[4] = {0x24, 0x85, 0x6b, 0xc3};
  uint32_t v;
  switch (s->state) {
    case S_SELECTOR:
      if (memcmp(s->word, SEL_DEADLINE, 4) == 0) {
        s->plan->has_deadline = true;
      } else if (memcmp(s->word, SEL_NO_DEADLINE, 4) != 0) {
        return fail(s);
      }
      s->state = S_HEAD;
      return next_at(s, s->pos);
    case S_HEAD:
      /* commands offset, inputs offset[, deadline]: relative to the body. */
      if (s->field == 2) {
        if (!narrow(s->word, 8, &s->plan->deadline)) return fail(s);
      } else if (!word_u32(s, s->field == 0 ? &s->base : &s->heads)) {
        return false;
      }
      if (++s->field < (s->plan->has_deadline ? 3 : 2)) {
        return next_at(s, s->pos);
      }
      s->state = S_CMDS_LEN;
      return next_at(s, (uint64_t)4 + s->base);
    case S_CMDS_LEN:
      if (!word_u32(s, &v)) return false;
      if (v == 0 || v > UR_MAX_STEPS) return fail(s);
      s->ncmds = (uint8_t)v;
      s->k = 0;
      s->state = S_CMDS;
      return next_at(s, s->pos);
    case S_INPUTS_LEN:
      if (!word_u32(s, &v)) return false;
      if (v != s->ncmds) return fail(s);
      s->heads = s->pos; /* element heads are relative to the first one */
      s->k = 0;
      s->state = S_INPUT_HEAD;
      return next_at(s, s->pos);
    case S_INPUT_HEAD:
      if (!word_u32(s, &s->elem[s->k])) return false;
      if (++s->k < s->ncmds) return next_at(s, s->pos);
      s->step = 0;
      return next_input(s);
    case S_ELEM_LEN: {
      if (!word_u32(s, &s->len)) return false;
      if (s->len > s->total - s->pos) return fail(s);
      s->base = s->pos;
      s->pstep = s->nsteps;
      UrStep* st = add_step(s);
      if (!st) return false;
      st->kind = (UrKind)current(s)->kind;
      s->field = 0;
      s->state = S_FIELD;
      if (s->cmds[s->step] == CMD_V4_SWAP) {
        memset(&s->v4, 0, sizeof(s->v4));
        s->state = S4_HEAD;
      }
      return next_in_input(s, 0);
    }
    case S_FIELD:
      return head_field(s);
    case S_DYN_LEN:
      return dyn_len(s);
    case S_V2_PATH:
      return v2_path_word(s);
    default:
      return v4_word(s);
  }
}

void ur_stream_begin(UrStream* s, UrPlan* out, size_t total) {
  memset(s, 0, sizeof(*s));
  memset(out, 0, sizeof(*out));
  s->plan = out;
  if (total > UINT32_MAX) {
    s->failed = true;
    return;
  }
  s->total = (uint32_t)total;
  s->state = S_SELECTOR;
}

bool ur_stream_feed(UrStream* s, const uint8_t* data, size_t len) {
  if (len > s->total - s->pos) {
    s->pos = s->total;
    return fail(s);
  }
  for (size_t i = 0; i < len && !s->failed; i++) {
    const uint32_t off = s->pos++;
    if (off < s->at || s->state == S_DONE) continue; /* not read */
    if (s->state == S_CMDS || s->state == S_V3_PATH || s->state == S4_ACTS) {
      on_byte(s, data[i]);
      continue;
    }
    s->word[s->got++] = data[i];
    if (s->got == (s->state == S_SELECTOR ? 4 : 32)) {
      s->got = 0;
      on_word(s);
    }
  }
  return !s->failed;
}

bool ur_stream_finish(UrStream* s) {
  if (s->failed || s->state != S_DONE || s->pos != s->total) {
    if (s->plan) memset(s->plan, 0, sizeof(*s->plan));
    s->failed = true;
    return false;
  }
  s->plan->n = s->nsteps;
  return true;
}

bool ur_decode(const uint8_t* calldata, size_t len, UrPlan* out) {
  UrStream s;
  ur_stream_begin(&s, out, len);
  if (calldata && len) ur_stream_feed(&s, calldata, len);
  return ur_stream_finish(&s);
}

bool ur_recipient_is_constant(const uint8_t recipient[20], uint8_t which) {
  for (int i = 0; i < 19; i++) {
    if (recipient[i] != 0) return false;
  }
  return recipient[19] == which;
}

/* The router itself, by placeholder or by its own address: either way it
 * holds the funds for a later step. Apps encode both. */
static bool is_router(const uint8_t r[20], const uint8_t router[20]) {
  return ur_recipient_is_constant(r, UR_RECIPIENT_ADDRESS_THIS) ||
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

/* a - floor(a * bips / 10000): what is left after BipsLibrary's portion.
 * a is at most a uint128 here, so the product fits. */
static bool minus_portion(const uint8_t a[32], uint16_t bips, uint8_t out[32]) {
  uint8_t p[32], q[32];
  uint32_t carry = 0;
  for (int i = 31; i >= 0; i--) {
    carry += (uint32_t)a[i] * bips;
    p[i] = (uint8_t)carry;
    carry >>= 8;
  }
  if (carry != 0) return false;
  uint32_t r = 0;
  for (int i = 0; i < 32; i++) {
    r = (r << 8) | p[i];
    q[i] = (uint8_t)(r / 10000);
    r %= 10000;
  }
  unsigned borrow = 0;
  for (int i = 31; i >= 0; i--) {
    const int d = (int)a[i] - q[i] - (int)borrow;
    out[i] = (uint8_t)d;
    borrow = d < 0;
  }
  return borrow == 0;
}

static bool is_swap(UrKind k) {
  return k == UR_V3_SWAP_EXACT_IN || k == UR_V3_SWAP_EXACT_OUT ||
         k == UR_V2_SWAP_EXACT_IN || k == UR_V2_SWAP_EXACT_OUT ||
         k == UR_V4_SWAP_EXACT_IN || k == UR_V4_SWAP_EXACT_OUT;
}

static bool is_exact_in(UrKind k) {
  return k == UR_V3_SWAP_EXACT_IN || k == UR_V2_SWAP_EXACT_IN ||
         k == UR_V4_SWAP_EXACT_IN;
}

/* A bips word: 1..10000. */
static bool fee_bips(const uint8_t a[32], uint16_t* bips) {
  if (!is_zero(a, 30)) return false;
  const unsigned v = ((unsigned)a[30] << 8) | a[31];
  if (v == 0 || v > 10000) return false;
  *bips = (uint16_t)v;
  return true;
}

/* The asset a step hands to someone other than the router. ETH (native) is
 * the zero address. */
typedef struct {
  bool set;
  bool eth;
  uint8_t token[20];
} Asset;

static bool same_asset(Asset* z, bool eth, const uint8_t token[20]) {
  if (!z->set) {
    z->set = true;
    z->eth = eth;
    if (!eth) memcpy(z->token, token, 20);
    return true;
  }
  return z->eth == eth && (eth || memcmp(z->token, token, 20) == 0);
}

static bool same_recipient(const uint8_t** r, const uint8_t* to,
                           const uint8_t router[20]) {
  if (is_router(to, router)) return false;
  if (!*r) *r = to;
  return memcmp(*r, to, 20) == 0;
}

/* A route is read as token flow through the router (uniswap_ur.h). The user
 * pays with one asset: msg.value, or one token pulled by the swaps it pays
 * for (payerIsUser). Every other swap is paid from what the router holds.
 * Exactly one asset reaches exactly one recipient: from swaps that deliver
 * to it, and from SWEEP / UNWRAP_WETH of what the router holds. The review
 * states the sum of what the user pays, the sum of the minimums every one
 * of those deliveries enforces, and at most one fee. */
/* Routers whose V4Router uses the ExactInputParams / ExactOutputParams
 * layout read above (with minHopPriceX36), checked against their verified
 * source. Older routers (UR 2.0) encode V4 swaps without that field: the
 * same bytes would read as different amounts there. */
static const uint8_t V4_ROUTERS[][20] = {
    /* Base, UR 2.1.2 */
    {0xd6, 0x14, 0x5b, 0x2d, 0x3f, 0x37, 0x99, 0x19, 0xe8, 0xcd,
     0xed, 0xa7, 0xb9, 0x7e, 0x37, 0xc4, 0xb2, 0xca, 0x9c, 0x40},
};

static bool v4_router(const uint8_t router[20]) {
  for (size_t i = 0; i < sizeof(V4_ROUTERS) / sizeof(V4_ROUTERS[0]); i++) {
    if (memcmp(V4_ROUTERS[i], router, 20) == 0) return true;
  }
  return false;
}

bool ur_summarize(const UrPlan* plan, const uint8_t router[20],
                  const uint8_t value[32], UrSummary* out) {
  memset(out, 0, sizeof(*out));
  if (!plan || plan->n == 0 || plan->n > UR_MAX_STEPS) return false;
  const bool eth = !is_zero(value, 32);
  const UrStep* permit = NULL;
  const UrStep* first_swap = NULL;
  const UrStep* last_swap = NULL;
  const UrStep* fee = NULL;
  const uint8_t* recipient = NULL;
  const uint8_t* payer_token = NULL;
  Asset z = {0};
  bool exact_in = true, uses_eth = false;
  uint8_t spent[32] = {0};

  /* Pass 1: what is paid, by whom, and what each swap delivers where. */
  for (uint8_t i = 0; i < plan->n; i++) {
    const UrStep* s = &plan->steps[i];
    switch (s->kind) {
      case UR_PERMIT2_PERMIT:
        if (i != 0) return false;
        permit = s;
        break;
      case UR_WRAP_ETH:
        /* Wraps msg.value (or, with none, what the router holds). */
        if (!is_router(s->recipient, router) ||
            !(is_balance_word(s->amount) ||
              (eth && memcmp(s->amount, value, 32) == 0))) {
          return false;
        }
        uses_eth = uses_eth || eth;
        break;
      case UR_UNWRAP_WETH:
      case UR_SWEEP:
      case UR_PAY_PORTION:
      case UR_V4_TAKE_PORTION:
        break; /* pass 2 */
      default: {
        if (!is_swap(s->kind)) return false; /* TRANSFER */
        if (!first_swap) {
          first_swap = s;
          exact_in = is_exact_in(s->kind);
        } else if (exact_in != is_exact_in(s->kind)) {
          return false;
        }
        last_swap = s;
        const bool v4 =
            s->kind == UR_V4_SWAP_EXACT_IN || s->kind == UR_V4_SWAP_EXACT_OUT;
        if (v4 && !v4_router(router)) return false;
        /* Only a V4 swap moves native ETH. */
        if (!v4 && (is_zero(s->token_in, 20) || is_zero(s->token_out, 20))) {
          return false;
        }
        if (s->payer_is_user) {
          /* The user's token, pulled through Permit2: one token only, and
           * never "the router's balance" taken from the user. */
          if (eth || is_balance_word(s->amount) ||
              (payer_token && memcmp(payer_token, s->token_in, 20) != 0)) {
            return false;
          }
          payer_token = s->token_in;
          if (!add32(spent, exact_in ? s->amount : s->limit)) return false;
        } else if (v4 && is_zero(s->token_in, 20)) {
          uses_eth = uses_eth || eth;
        }
        if (!is_router(s->recipient, router)) {
          if (!same_recipient(&recipient, s->recipient, router) ||
              !same_asset(&z, v4 && is_zero(s->token_out, 20), s->token_out)) {
            return false;
          }
        }
        break;
      }
    }
  }
  if (!first_swap) return false;

  /* Input side. */
  if (eth) {
    /* msg.value must be put to use: wrapped, or settled into a V4 pool. */
    if (!uses_eth || permit) return false;
    if (!exact_in) {
      /* Exact output may not be allowed to spend more than was sent. */
      uint8_t limits[32] = {0};
      for (uint8_t i = 0; i < plan->n; i++) {
        const UrStep* s = &plan->steps[i];
        if (is_swap(s->kind) && !add32(limits, s->limit)) return false;
      }
      if (memcmp(limits, value, 32) > 0) return false;
    }
    out->in_is_eth = true;
    memcpy(out->token_in, first_swap->token_in, 20);
    memcpy(out->amount_in, value, 32);
  } else {
    if (!payer_token) return false;
    memcpy(out->token_in, payer_token, 20);
    memcpy(out->amount_in, spent, 32);
  }
  if (permit) {
    if (memcmp(permit->token_out /* spender */, router, 20) != 0 ||
        memcmp(permit->token_in, payer_token, 20) != 0) {
      return false;
    }
    out->has_permit = true;
    memcpy(out->permit_token, permit->token_in, 20);
    memcpy(out->permit_amount, permit->amount, 32);
    out->permit_expiration = permit->expiration;
  }

  /* Pass 2: the asset delivered from the router, the recipient, the fee. */
  bool from_router_step = false;
  for (uint8_t i = 0; i < plan->n && !z.set; i++) {
    const UrStep* s = &plan->steps[i];
    if (s->kind == UR_SWEEP) {
      same_asset(&z, is_zero(s->token_in, 20), s->token_in);
    } else if (s->kind == UR_UNWRAP_WETH && !is_router(s->recipient, router)) {
      same_asset(&z, true, NULL);
    }
  }
  if (!z.set) return false; /* nothing reaches anyone */
  uint8_t direct[32] = {0}, swept[32] = {0}, held[32] = {0};
  /* unswept: a swap left the asset in the router after its last SWEEP.
   * SWEEP moves only what the router holds when it runs. */
  bool consumed = false, unswept = false;
  for (uint8_t i = 0; i < plan->n; i++) {
    const UrStep* s = &plan->steps[i];
    uint8_t g[32];
    switch (s->kind) {
      case UR_SWEEP:
      case UR_UNWRAP_WETH: {
        const bool is_eth =
            s->kind == UR_UNWRAP_WETH || is_zero(s->token_in, 20);
        if (s->kind == UR_UNWRAP_WETH && is_router(s->recipient, router)) {
          consumed = consumed || !z.eth; /* WETH -> ETH inside the route */
          break;
        }
        if (!same_recipient(&recipient, s->recipient, router)) return false;
        if (z.eth != is_eth || (!is_eth && memcmp(z.token, s->token_in, 20))) {
          /* Only leftover ETH may go back besides the asset (clean-up). */
          if (!is_eth) return false;
          break;
        }
        if (is_balance_word(s->amount) || !add32(swept, s->amount)) {
          return false;
        }
        from_router_step = true;
        unswept = false;
        break;
      }
      case UR_PAY_PORTION:
      case UR_V4_TAKE_PORTION: {
        uint16_t bips;
        if (fee || !fee_bips(s->amount, &bips) ||
            is_router(s->recipient, router)) {
          return false;
        }
        fee = s;
        out->has_fee = true;
        out->fee_bips = bips;
        memcpy(out->fee_recipient, s->recipient, 20);
        break;
      }
      default:
        if (!is_swap(s->kind)) break;
        memcpy(g, exact_in ? s->limit : s->amount, 32);
        if (!is_router(s->recipient, router)) {
          const UrStep* next = i + 1 < plan->n ? &plan->steps[i + 1] : NULL;
          if (next && next->kind == UR_V4_TAKE_PORTION) {
            /* The fee comes out of this swap's credit before TAKE. */
            uint16_t bips;
            if (!exact_in || !fee_bips(next->amount, &bips) ||
                !minus_portion(s->limit, bips, g)) {
              return false;
            }
          }
          if (!add32(direct, g)) return false;
        } else if (!z.eth && memcmp(s->token_out, z.token, 20) == 0) {
          if (!add32(held, g)) return false;
          unswept = true;
        }
        if (!s->payer_is_user && !z.eth &&
            memcmp(s->token_in, z.token, 20) == 0) {
          consumed = true; /* the router spends the asset again */
        }
        break;
    }
  }
  if (!recipient || unswept) return false;
  if (fee) {
    /* PAY_PORTION takes from what the router holds for the user (the
     * token, or WETH/ETH before an unwrap); TAKE_PORTION from its own
     * swap's output, which must deliver to the user. */
    if (fee->kind == UR_PAY_PORTION) {
      bool held_fee = !z.eth ? memcmp(fee->token_in, z.token, 20) == 0
                             : is_zero(fee->token_in, 20);
      for (uint8_t i = 0; i < plan->n && !held_fee && z.eth; i++) {
        const UrStep* s = &plan->steps[i];
        held_fee = is_swap(s->kind) && is_router(s->recipient, router) &&
                   memcmp(s->token_out, fee->token_in, 20) == 0;
      }
      if (!held_fee || !from_router_step) return false;
    } else {
      const UrStep* swap = fee - 1;
      if (fee == plan->steps || swap->kind != UR_V4_SWAP_EXACT_IN ||
          is_router(swap->recipient, router)) {
        return false;
      }
    }
  }
  /* What the router holds for the user: its SWEEP / UNWRAP minimums, or,
   * with no fee taken from it and nothing spending it again, the larger
   * of those and the minimums of the swaps that filled it (apps put the
   * floor on one or the other). An unwrap's WETH is not identifiable, so
   * only its own minimum counts. */
  uint8_t from_router[32];
  memcpy(from_router, swept, 32);
  if ((!fee || fee->kind != UR_PAY_PORTION) && !consumed && !z.eth &&
      memcmp(held, swept, 32) > 0) {
    memcpy(from_router, held, 32);
  }
  if (!add32(direct, from_router)) return false;

  out->exact_in = exact_in;
  out->out_is_eth = z.eth;
  memcpy(out->token_out, z.eth ? last_swap->token_out : z.token, 20);
  memcpy(out->amount_out, direct, 32);
  out->recipient_is_sender =
      ur_recipient_is_constant(recipient, UR_RECIPIENT_MSG_SENDER);
  memcpy(out->recipient, recipient, 20);
  out->n_hooks = plan->n_hooks;
  memcpy(out->hooks, plan->hooks, sizeof(out->hooks));
  return true;
}
