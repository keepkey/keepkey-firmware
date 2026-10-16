/*
 * erc7730-validate: run a compiled ERC-7730 program through the firmware's own
 * streaming catalog verifier, so the host compiler is checked against the
 * parser the device actually runs.
 *
 * The program is wrapped in a K773 envelope with an empty Merkle proof and an
 * all-zero delegate record. Authentication must fail -- no signer is loaded
 * -- so the only acceptable result is ERC7730_CATALOG_UNTRUSTED, which the
 * verifier returns only after the envelope and every program section have
 * parsed. BAD_PROGRAM/BAD_ENVELOPE/BAD_SEQUENCE mean the device would refuse
 * the program. The envelope is fed in odd-sized chunks, as a host would.
 *
 * Usage: erc7730-validate <program-file>; exit 0 when the device parser
 * accepts it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keepkey/firmware/erc7730_catalog.h"
#include "trezor/crypto/sha2.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <program-file>\n", argv[0]);
    return 2;
  }
  FILE* f = fopen(argv[1], "rb");
  if (!f) {
    perror(argv[1]);
    return 2;
  }
  static uint8_t envelope[1u << 20];
  const size_t head = 10;
  const size_t program_limit = sizeof(envelope) - head - 512;
  /* A read ending exactly at the limit does not set EOF. Keep one byte of
   * lookahead in the reserved envelope suffix to distinguish that case. */
  const size_t program_len = fread(envelope + head, 1, program_limit + 1, f);
  const int read_error = ferror(f);
  fclose(f);
  if (read_error) {
    fprintf(stderr, "%s: could not read program\n", argv[1]);
    return 2;
  }
  if (program_len == 0 || program_len > program_limit) {
    fprintf(stderr, "%s: empty or too large\n", argv[1]);
    return 2;
  }
  memcpy(envelope, "K773", 4);
  envelope[4] = 1;
  envelope[5] = 1;
  for (int i = 0; i < 4; i++)
    envelope[6 + i] = (uint8_t)(program_len >> (24 - 8 * i));
  size_t len = head + program_len;
  envelope[len++] = 0; /* empty proof: the leaf is the catalog root */
  envelope[len++] = 0;
  envelope[len++] = ERC7730_DELEGATE_RECORD_LEN;
  memset(envelope + len, 0, ERC7730_DELEGATE_RECORD_LEN + 64);
  len += ERC7730_DELEGATE_RECORD_LEN + 64;
  envelope[len++] = 0; /* recovery */

  uint8_t id[32];
  sha256_Raw(envelope, len, id);
  Erc7730CatalogVerifier verifier;
  Erc7730CatalogIdentity identity;
  memset(&identity, 0, sizeof(identity));
  erc7730_catalog_begin(&verifier, id, (uint32_t)len);
  Erc7730CatalogResult result = ERC7730_CATALOG_MORE;
  for (size_t offset = 0; offset < len && result == ERC7730_CATALOG_MORE;) {
    const size_t chunk = len - offset < 37 ? len - offset : 37;
    result = erc7730_catalog_feed(&verifier, (uint32_t)offset,
                                  envelope + offset, chunk, &identity);
    offset += chunk;
  }
  erc7730_catalog_abort(&verifier);
  if (result != ERC7730_CATALOG_UNTRUSTED) {
    fprintf(stderr, "%s: device verifier refused the program (result %d)\n",
            argv[1], (int)result);
    return 1;
  }
  return 0;
}
