/* Official ZIP-244 (v5) vectors from zcash/zcash-test-vectors,
 * test-vectors/json/zip_0244.json at commit
 * 113b3914c79dfe7eb68cb754cd7fea20b75e2e61 (generator
 * zcash_test_vectors/zip_0244.py, NU5 branch 0xc2d6d0b4). The same vectors
 * ship in librustzcash zcash_primitives/src/transaction/tests/data.rs.
 *
 * Coinbase vectors 1 and 2 are left out; the device never signs coinbase.
 * txid, sighash_shielded, sighash_all, amounts and script_pubkeys are copied
 * verbatim. The other fields are split out of the vector's raw tx bytes:
 * header, vin and vout as serialized, and sapling_digest and orchard_digest
 * hashed per ZIP-244 T.3/T.4 by a parser outside this repo. That parse
 * reproduces every vector's txid and auth_digest, and the test checks txid
 * again through the firmware, so a wrong extraction fails the test. Hex
 * strings in wire byte order. */
#ifndef KEEPKEY_UNITTESTS_ZCASH_ZIP244_VECTORS_H
#define KEEPKEY_UNITTESTS_ZCASH_ZIP244_VECTORS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  const char* prevout_txid;
  uint32_t prevout_index;
  uint32_t sequence;
  uint64_t amount;
  const char* script_pubkey;
} Zip244TxIn;

typedef struct {
  uint64_t value;
  const char* script_pubkey;
} Zip244TxOut;

typedef struct {
  int index; /* position in zip_0244.json */
  uint32_t version_group_id;
  uint32_t branch_id;
  uint32_t lock_time;
  uint32_t expiry_height;
  const Zip244TxIn* inputs;
  size_t n_inputs;
  const Zip244TxOut* outputs;
  size_t n_outputs;
  const char* sapling_digest;
  const char* orchard_digest;
  const char* txid;
  const char* sighash_shielded;
  int transparent_input; /* -1: none */
  const char* sighash_all;
} Zip244Vector;

static const Zip244TxIn kZip244V0Inputs[] = {
    {"e152a8049e294c4d6e66b164939daffa2ef6ee6921481cdd86b3cc4318d9614f",
     1569726664u, 0x8849f2a3u, UINT64_C(1800841178198868), "650051"}};
static const Zip244TxIn kZip244V3Inputs[] = {
    {"e7d3419b1fca265a5559cf9e2d3b60978d81a678b9ed8e4486b4d14609d6c127",
     4294689472u, 0xf1bff760u, UINT64_C(1583482237960570),
     "525351636a53acac63"}};
static const Zip244TxOut kZip244V3Outputs[] = {
    {UINT64_C(935446795463426), "516a005251516a5251"},
    {UINT64_C(277706699548862), "6a6a53656552"}};
static const Zip244TxIn kZip244V4Inputs[] = {
    {"51d6006becf8d2ffb03990f67774a81e05b7f4bbad8577fa27c9de64e1b11dcf",
     1448693560u, 0x65c3100bu, UINT64_C(754044915413924), "ac6a53656aac"},
    {"7ebac03bfc0b587bef2f45ec8acdaa51c143b0cb25b9142c61bd790a80d7c23f",
     1224985744u, 0x3e84d2e4u, UINT64_C(637640651332574), "536aac6a00006a63"}};
static const Zip244TxOut kZip244V4Outputs[] = {
    {UINT64_C(646237202206608), "636aacac6a005100"},
    {UINT64_C(389003185263136), "ac6a6a00"}};
static const Zip244TxIn kZip244V5Inputs[] = {
    {"605a064f69219f1dc0d00b3b48642f970dc00cca4b8b43308be18286ec5a4288",
     2023948502u, 0xc6a468d4u, UINT64_C(640769667462895), "656a52"},
    {"969b3792f2485027d0ad9aa4a9c2cc972f9ee5190a95b1eb058dddd8c08e7d75",
     453074495u, 0xf2c4c152u, UINT64_C(1001666677832046), "656a515151"}};
static const Zip244TxOut kZip244V5Outputs[] = {
    {UINT64_C(737846128122805), "ac00"},
    {UINT64_C(108018631040012), "5263ac5353"}};
static const Zip244TxIn kZip244V6Inputs[] = {
    {"488eb7cf33f6dad1666a05f91ad7757965c29936e7fa48d77e89ee0962f58c05",
     1439699229u, 0x261b8a08u, UINT64_C(741599467359839), "5365ac"},
    {"48b8174cbcfc8b5b5cd077115afde18405054e5da9a04310342c5d3b526e0b02",
     571984581u, 0xd123eedeu, UINT64_C(1790607082653742),
     "005252ac6363525163"}};
static const Zip244TxIn kZip244V7Inputs[] = {
    {"af247e36483f13b204422237fc6ab3eba02fc4142b4297ebb5683db8d2431970",
     2943013482u, 0x40b7531cu, UINT64_C(1286021364285659), "00655153530053ac"},
    {"f34543a6b3e9f5bb7d5c49e8c37f614921254f3212394c797d1cee7899b7b4b6",
     884431195u, 0x7431b770u, UINT64_C(1442199005815061), "6aac516553"},
    {"14438cd80bd0f9a67c9b9e552f013c115a954f35e0616c68d43163d334dac382",
     2917479280u, 0xc635598fu, UINT64_C(1925025507443299), ""}};
static const Zip244TxOut kZip244V7Outputs[] = {
    {UINT64_C(1137235018051130), "5353636365"},
    {UINT64_C(1493656723411665), "0000ac52006a5263"},
    {UINT64_C(1689347370275509), "6a6a51"}};
static const Zip244TxOut kZip244V9Outputs[] = {
    {UINT64_C(1447550772213337), "516551"}};
static const Zip244Vector kZip244Vectors[] = {
    {0, 0x26a7270au, 0xc2d6d0b4u, 2591264634u, 36466477u, kZip244V0Inputs, 1,
     NULL, 0,
     "4ae5dd1bfb8c15bc3de59ab71530912abe24059b10665722f3fb8fae9b55006c",
     "b2195dc01bb5fecb74ee2576e513de9d06ad48f32a8f37a080a38338de2872ca",
     "552c96bd33834ba1a8a3ecd80a2c9cb41187553a3dcfe7928316bb70704b85d0",
     "88da64b95b56d8296ab1f721eb5be66d0fd478f2b96b93d5dcee8f7a1000b0ff", 0,
     "2d4ebf4d424238ad0bc2469970347eaf767ff906958e35107fd22c1dc536e459"},
    {3, 0x26a7270au, 0xc2d6d0b4u, 3763875072u, 15000943u, kZip244V3Inputs, 1,
     kZip244V3Outputs, 2,
     "5631378a8d1ef764389e1f16cd43f06bbff6f458fa6a2e57499c703297e22d79",
     "08f024df11da48f183daf3b1af6eca3f428382dca8ab0606395918b1907e9404",
     "fa73831eb8787bdf28d6bfc013884161cdf6d3fc18478c4c7d071e5f2076b610",
     "40ebf69f1549f4b8e553aca27c7ef910357ba038ec45af240ffef69e60aa41e8", 0,
     "b8af5244a13abc13a73999926a5070328cfc3b6be20a3c85373e68300da27918"},
    {4, 0x26a7270au, 0xc2d6d0b4u, 2377642351u, 353784540u, kZip244V4Inputs, 2,
     kZip244V4Outputs, 2,
     "6f2fc8f98feafd94e74a0df4bed74391ee0b5a69945e4ced8ca8a095206f00ae",
     "bc5294d5d6904899268adc3da0edad8fa5b7e85314298928a3abe72f3a1accda",
     "35ff79dca2b2492acf3ed9757a00a57892c661d2b68f229a6177c0f86feb2e4c",
     "4a4ee3b6c7fbf675f0213ab1a62b7c4b86b1bd5e8664e6ed0edaaa458e5ae4c1", 0,
     "92dc54223e4fd679b98c146f10d3a56fd81ab5dc843cb110af9857649eb518d5"},
    {5, 0x26a7270au, 0xc2d6d0b4u, 1023346065u, 370596274u, kZip244V5Inputs, 2,
     kZip244V5Outputs, 2,
     "6f2fc8f98feafd94e74a0df4bed74391ee0b5a69945e4ced8ca8a095206f00ae",
     "bc2aedb8be887411efe3ce53557b39656abfa4dc607e1b947a002f994d022fb8",
     "96a43bb156156c1d66a6811314110d5fade5d0b1cc15e5cd043901bce4e3d950",
     "fd1a16a96fe084055afe2f565c74c0ef2d59cbcea68efc9edd14c9df8e630216", 0,
     "96b5062d89928f4d8ec30cd8248c0b32823743376002c561cafaf620aeaff5c5"},
    {6, 0x26a7270au, 0xc2d6d0b4u, 1080739450u, 180198152u, kZip244V6Inputs, 2,
     NULL, 0,
     "6f2fc8f98feafd94e74a0df4bed74391ee0b5a69945e4ced8ca8a095206f00ae",
     "238671e398cde31c414c1747dda8b3f2c2608cf55557df3f15cc22306de663e9",
     "1b66bbce2146b688a21ecd2baa0ba5c0c17c55344c00a22c57470bfd1499bc01",
     "7b5ad2a883b5a909f8c4b543b848f7ba6379eaaa9494813d7abf8584f8ca0611", 1,
     "941cbae22ac25e72df6a92ea3949137c9fb5a7b8c44a29f26c75860f3523b6a8"},
    {7, 0x26a7270au, 0xc2d6d0b4u, 619103442u, 3407014u, kZip244V7Inputs, 3,
     kZip244V7Outputs, 3,
     "0b70faff3ab1e59f474b7b4de721d65428887ccd6c68f8b111d06b65e58137ce",
     "9fbe4ed13b0c08e671c11a3407d84e1117cd45028a2eee1b9feae78b48a6e2c1",
     "de856240f2269baf1b9eacb2dbd65c9ad80ed8407f7995fc11e1049811192b12",
     "d75a217491b64af89b007ab47936ff3c934cd9eb0b045c67bbdd0231c10b7458", 2,
     "76bda2a801e429ecd10692d64e3e189031d3a8f0114f5547ac9020e62543b896"},
    {8, 0x26a7270au, 0xc2d6d0b4u, 1813567528u, 72413405u, NULL, 0, NULL, 0,
     "e0b8bc0fb1c6502f3e0097eec36e1bfaf4d825fc579ebbe1c5aac64e37bfd327",
     "d952ddb08079cccac758bab56990a267d034f14449e0dfa1ac073c8981be5be6",
     "da42b538d2c15b8183cadd3ec02c2f98ad8a57a7bad6186cf9f29315e75d96b5",
     "da42b538d2c15b8183cadd3ec02c2f98ad8a57a7bad6186cf9f29315e75d96b5", -1,
     NULL},
    {9, 0x26a7270au, 0xc2d6d0b4u, 3050072300u, 67311599u, NULL, 0,
     kZip244V9Outputs, 1,
     "855b83f68b414256cd6ecb1cdee7d7da0c4d0ceccf676595ea99189e5399d201",
     "9fbe4ed13b0c08e671c11a3407d84e1117cd45028a2eee1b9feae78b48a6e2c1",
     "13303f008095bf1624be62abb900b6973d7daffd413aa0e3a7d684e769e4ca45",
     "13303f008095bf1624be62abb900b6973d7daffd413aa0e3a7d684e769e4ca45", -1,
     NULL},
};

#endif
