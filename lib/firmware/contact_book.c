#include "keepkey/firmware/contact_book.h"

#include <string.h>

#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"

#define REQUEST_MAGIC "KKABREQ1"
#define ROOT_MAGIC "KKABRT01"
#define PROOF_MAGIC "KKABPRF1"
#define CONTACT_BOOK_VERSION 1

static bool proof_available;
static ContactBookEntry proof_entry;

static uint32_t read_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static void write_be32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static bool label_valid(const uint8_t* label, size_t len) {
  if (len == 0 || len > CONTACT_BOOK_LABEL_MAX) return false;
  /* "Alice" and "Alice " must not be two contacts, nor a label be blank. */
  if (label[0] == ' ' || label[len - 1] == ' ') return false;
  for (size_t i = 0; i < len; i++) {
    /* Alpha format is deliberately ASCII-only: no controls, bidi overrides,
     * invisible Unicode, or display-confusable normalization. */
    if (label[i] < 0x20 || label[i] > 0x7e || label[i] == '%') return false;
    /* Padding could push text onto another line of the review. */
    if (i && label[i] == ' ' && label[i - 1] == ' ') return false;
  }
  return true;
}

static bool network_valid(const uint8_t* network, size_t len) {
  if (len == 0 || len > CONTACT_BOOK_NETWORK_MAX) return false;
  bool colon = false;
  for (size_t i = 0; i < len; i++) {
    if (network[i] == ':') colon = true;
    if (!((network[i] >= 'a' && network[i] <= 'z') ||
          (network[i] >= 'A' && network[i] <= 'Z') ||
          (network[i] >= '0' && network[i] <= '9') || network[i] == ':' ||
          network[i] == '-'))
      return false;
  }
  return colon;
}

static void leaf_hash(const ContactBookEntry* entry, uint8_t out[32]) {
  SHA256_CTX ctx;
  uint8_t network_len = (uint8_t)strlen(entry->network);
  uint8_t label_len = (uint8_t)strlen(entry->label);
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t*)"KKABLEAF", 8);
  sha256_Update(&ctx, &network_len, 1);
  sha256_Update(&ctx, (const uint8_t*)entry->network, network_len);
  sha256_Update(&ctx, &entry->destination_type, 1);
  sha256_Update(&ctx, &entry->destination_len, 1);
  sha256_Update(&ctx, entry->destination, entry->destination_len);
  sha256_Update(&ctx, &label_len, 1);
  sha256_Update(&ctx, (const uint8_t*)entry->label, label_len);
  sha256_Final(&ctx, out);
}

static void pair_hash(const uint8_t left[32], const uint8_t right[32],
                      uint8_t out[32]) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, left, 32);
  sha256_Update(&ctx, right, 32);
  sha256_Final(&ctx, out);
}

static uint8_t tree_depth(uint8_t count) {
  uint8_t depth = 0, width = 1;
  while (width < count) {
    width <<= 1;
    depth++;
  }
  return depth;
}

static void merkle_root(const ContactBookEntry* entries, uint8_t count,
                        uint8_t out[32]) {
  uint8_t nodes[CONTACT_BOOK_MAX_ENTRIES][32];
  uint8_t width = 1;
  while (width < count) width <<= 1;
  for (uint8_t i = 0; i < count; i++) leaf_hash(&entries[i], nodes[i]);
  for (uint8_t i = count; i < width; i++)
    memcpy(nodes[i], nodes[count - 1], 32);
  while (width > 1) {
    for (uint8_t i = 0; i < width; i += 2)
      pair_hash(nodes[i], nodes[i + 1], nodes[i / 2]);
    width >>= 1;
  }
  memcpy(out, nodes[0], 32);
  memzero(nodes, sizeof(nodes));
}

bool contact_book_parse_request(
    const uint8_t* data, size_t data_len, ContactBookManifest* manifest,
    ContactBookEntry entries[CONTACT_BOOK_MAX_ENTRIES], size_t* signed_len) {
  if (!data || !manifest || !entries || data_len < 14 ||
      memcmp(data, REQUEST_MAGIC, 8) != 0 || data[8] != CONTACT_BOOK_VERSION)
    return false;
  size_t off = 9;
  manifest->revision = read_be32(data + off);
  off += 4;
  manifest->count = data[off++];
  if (manifest->revision == 0 || manifest->count == 0 ||
      manifest->count > CONTACT_BOOK_MAX_ENTRIES)
    return false;
  memset(entries, 0, sizeof(ContactBookEntry) * CONTACT_BOOK_MAX_ENTRIES);
  for (uint8_t i = 0; i < manifest->count; i++) {
    if (off + 5 > data_len) return false;
    uint8_t network_len = data[off++];
    if (off + network_len + 3 > data_len ||
        !network_valid(data + off, network_len))
      return false;
    memcpy(entries[i].network, data + off, network_len);
    off += network_len;
    entries[i].destination_type = data[off++];
    entries[i].destination_len = data[off++];
    if (entries[i].destination_type == 0 || entries[i].destination_len == 0 ||
        entries[i].destination_len > CONTACT_BOOK_DESTINATION_MAX ||
        off + entries[i].destination_len + 1 > data_len)
      return false;
    memcpy(entries[i].destination, data + off, entries[i].destination_len);
    off += entries[i].destination_len;
    uint8_t len = data[off++];
    if (off + len > data_len || !label_valid(data + off, len)) return false;
    memcpy(entries[i].label, data + off, len);
    entries[i].label[len] = '\0';
    off += len;
    /* One name per address and one address per name on a network: otherwise
     * the host chooses which of two certified answers the device shows. */
    for (uint8_t j = 0; j < i; j++) {
      if (strcmp(entries[j].network, entries[i].network) != 0) continue;
      if (strcmp(entries[j].label, entries[i].label) == 0 ||
          (entries[j].destination_type == entries[i].destination_type &&
           entries[j].destination_len == entries[i].destination_len &&
           memcmp(entries[j].destination, entries[i].destination,
                  entries[i].destination_len) == 0))
        return false;
    }
  }
  if (off != data_len) return false;
  merkle_root(entries, manifest->count, manifest->root);
  if (signed_len) *signed_len = off;
  return true;
}

void contact_book_manifest_bytes(const ContactBookManifest* manifest,
                                 uint8_t out[46]) {
  memcpy(out, ROOT_MAGIC, 8);
  out[8] = CONTACT_BOOK_VERSION;
  write_be32(out + 9, manifest->revision);
  out[13] = manifest->count;
  memcpy(out + 14, manifest->root, 32);
}

bool contact_book_process_proof(const uint8_t* data, size_t data_len,
                                const uint8_t expected_pubkey[33]) {
  contact_book_clear();
  /* magic + manifest + pubkey + sig + entry + index/depth */
  if (!data || !expected_pubkey || data_len < 8 + 38 + 33 + 64 + 8 ||
      memcmp(data, PROOF_MAGIC, 8) != 0 || data[8] != CONTACT_BOOK_VERSION)
    return false;
  size_t off = 9;
  ContactBookManifest manifest;
  manifest.revision = read_be32(data + off);
  off += 4;
  manifest.count = data[off++];
  memcpy(manifest.root, data + off, 32);
  off += 32;
  if (manifest.revision == 0 || manifest.count == 0 ||
      manifest.count > CONTACT_BOOK_MAX_ENTRIES)
    return false;
  const uint8_t* pubkey = data + off;
  off += 33;
  const uint8_t* signature = data + off;
  off += 64;
  if (memcmp(pubkey, expected_pubkey, 33) != 0) return false;

  if (off + 5 > data_len) return false;
  ContactBookEntry entry;
  memset(&entry, 0, sizeof(entry));
  uint8_t network_len = data[off++];
  if (off + network_len + 3 > data_len ||
      !network_valid(data + off, network_len))
    return false;
  memcpy(entry.network, data + off, network_len);
  off += network_len;
  entry.destination_type = data[off++];
  entry.destination_len = data[off++];
  if (entry.destination_type == 0 || entry.destination_len == 0 ||
      entry.destination_len > CONTACT_BOOK_DESTINATION_MAX ||
      off + entry.destination_len + 1 > data_len)
    return false;
  memcpy(entry.destination, data + off, entry.destination_len);
  off += entry.destination_len;
  uint8_t label_len = data[off++];
  if (off + label_len + 2 > data_len || !label_valid(data + off, label_len))
    return false;
  memcpy(entry.label, data + off, label_len);
  off += label_len;
  uint8_t index = data[off++];
  uint8_t depth = data[off++];
  if (index >= manifest.count || depth != tree_depth(manifest.count) ||
      depth > CONTACT_BOOK_MAX_DEPTH || off + (size_t)depth * 32 != data_len)
    return false;

  uint8_t hash[32], combined[32];
  leaf_hash(&entry, hash);
  uint8_t cursor = index;
  for (uint8_t i = 0; i < depth; i++) {
    const uint8_t* sibling = data + off + (size_t)i * 32;
    if (cursor & 1)
      pair_hash(sibling, hash, combined);
    else
      pair_hash(hash, sibling, combined);
    memcpy(hash, combined, 32);
    cursor >>= 1;
  }
  if (memcmp(hash, manifest.root, 32) != 0) {
    memzero(&entry, sizeof(entry));
    return false;
  }

  uint8_t encoded[46], digest[32];
  contact_book_manifest_bytes(&manifest, encoded);
  sha256_Raw(encoded, sizeof(encoded), digest);
  bool ok = ecdsa_verify_digest(&secp256k1, pubkey, signature, digest) == 0;
  memzero(encoded, sizeof(encoded));
  memzero(digest, sizeof(digest));
  memzero(hash, sizeof(hash));
  memzero(combined, sizeof(combined));
  if (!ok) {
    memzero(&entry, sizeof(entry));
    return false;
  }
  proof_entry = entry;
  proof_available = true;
  memzero(&entry, sizeof(entry));
  return true;
}

bool contact_book_match(const char* network, uint8_t destination_type,
                        const uint8_t* destination, size_t destination_len) {
  return proof_available && network && destination &&
         strcmp(proof_entry.network, network) == 0 &&
         proof_entry.destination_type == destination_type &&
         proof_entry.destination_len == destination_len &&
         memcmp(proof_entry.destination, destination, destination_len) == 0;
}

const char* contact_book_label(void) {
  return proof_available ? proof_entry.label : NULL;
}

void contact_book_clear(void) {
  proof_available = false;
  memzero(&proof_entry, sizeof(proof_entry));
}
