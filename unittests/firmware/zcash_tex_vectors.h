/* ZIP 320 TEX payment fixtures built by librustzcash (zcash_primitives
 * Builder::build_for_pczt, pczt Creator + IoFinalizer; orchard 0.16.0) for
 * the "all x12" seed, account 0, on regtest (zcash_pool_migration example
 * kktex). Sighashes are pczt Signer::shielded_sighash and transparent_sighash.
 *
 * Step 1 (v6, NU6.3): one 1,025,000-zat Orchard note to the account's
 * one-time address m/44'/133'/0'/2/0, 1,010,000 zat, ZIP 317 fee 15,000, no
 * change. Orchard bundle flags 0x03, value balance 1,025,000, two actions: a
 * dummy and the wallet's spend paired with a fabricated zero-value output.
 *
 * Step 2 (v6 NU6.3, and v5 NU6.2): that one-time output to the TEX address
 * tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte (the ZIP 320 example), 1,000,000
 * zat, fee 10,000. Transparent-only: no shielded bundle. Hex as on the wire. */
#ifndef KEEPKEY_UNITTESTS_ZCASH_TEX_VECTORS_H
#define KEEPKEY_UNITTESTS_ZCASH_TEX_VECTORS_H

#include "zcash_migration_vectors.h"

static const ZcashMigrationAction kZcashTexStep1Orchard[] = {
    {/* is_spend */ false,
    /* nullifier */
    "a593b9cd40c49a4f447d87ed1f01b5896b1135ee7739d7fdb04ad1a6eeda232f",
    /* rk */
    "6742b6a24175e6157151140a7ed464e4236a78785183c58a0eadc9a00e22dea4",
    /* alpha */
    "0b9ad8d7306dba1cb592962db3ffec30ca18fe3cdcef51c199eaad4615b57d3e",
    /* cv_net */
    "a41f06ec4122d79c0442c06a04c8d9a623c87d94a1e994787ec2acfb13288587",
    /* cmx */
    "ff61e8171bc34a00c43a2824b016c089b467313e51e02d776dcbc13c4dc7d10f",
    /* epk */
    "676ed987d25b96b7ff4ef38bf414f74e884e79012ba1db7d6090e37d7e9cb126",
    /* enc */
    "ffd7c80499607ed7ff8ccf36ea23890a40dbfbe7e1e2f4c4ecc9c719ec38bfd3"
    "7022afc69a91121396c96183645bc6f2cf4a8b2c1455fb81ce815ed964e2788e"
    "7db82875c8d9a6ac4235b5d1ac954b906c7181b97ed1aae6641b2d2ed4a41d20"
    "5b61d2bf0faabfa6512ffdaff000525efb96acf524120155847b45e3938e30c8"
    "310202deb697351458742efe591c95865f2348c220d17318dcacf183e4ae6e15"
    "302a4bcea524810ae1c70d50ee0aa9dd90546e7a6345922297220454c6a97b44"
    "4a926be368679a31535c95932daeb1aed9fcda3000cf0963c4105fd9bc6fd24b"
    "84062be96d06debd41f20332dc4d4291ec2b2f9364ba0f6cbc6f90da6729d0ee"
    "c6417a722c38c893f7e9113698f4ecde3ec560c37d88a8bd6bd04f2b1d86a06e"
    "84695c69b0333913ae81492981b4bff367998995ea689a705113346cb81ccdad"
    "6cbc5fc0733b97cefb92ce0b335bab1f492ac38da4c2384c005d7e2a352467d2"
    "e8544f9664df46950a3207edcfefd983e8495f53c214f19a9024c0c54a15fa75"
    "b80166313f550dbe42fa71704620bb78ed7273d5e5af8760b330278306da8098"
    "da3cbf3a640dc60aea3642e2b59a7902e61f89d3396c25d4692881f7de250e51"
    "e72300866c789036f550c3008b3865c89101b8925fee8abcddbd08b72ae9933f"
    "812f52f5d7705a105f66d0b4dfd16bde4211a08c6740c3887b1356a1744ddd81"
    "6f7c6e9dd2d682df1d14603ad69aa684587ea09c2fd25f746798c604fa3d7b07"
    "cb1ab7170a18b380cdd2fd3d539039d21a1e264d4cc9803170c3931408d2fd2c"
    "16310cf7",
    /* out */
    "8e54a7b6418db19c27eb768c3c754113eaa575de83023862634fb40ccb87c17c"
    "043be6f0d883754e2fd337dae19d79fe27c4904ab28ffc360681ffb6f8e871ed"
    "fd6684d6b5e23c4e0ec28d3a951f5d3f",
    /* recipient */
    "66faa653531d4a8acdf5096f756577b19962df6615641e5fe2db3a324970a7ff"
    "e546a1f97b073e94f7b238",
    /* rseed */
    "716070a992fff0e13dd67cc3ddaef4ada426aa5f4ec0f13668a6f4f537ad545e",
     /* value */ 0},
    {/* is_spend */ true,
    /* nullifier */
    "0440da65e51ce699977111262432473c28e06b12c3e5e38fc742f35b0fd02429",
    /* rk */
    "fec66ad4c564961f7af701ffbc1f1e2eb3abf8b4bbf1404d60aa9efc0881e585",
    /* alpha */
    "83969789048b1dc71a91d523c61624cc84894ddd64c4b8dc4380e08a327f4820",
    /* cv_net */
    "c7343ce3e707ccdbfac1e3cae1acbef5701e793e107efe264d027af10ab73e31",
    /* cmx */
    "a34f6a687d5ad6aae53f0225144324a070a7de1066a9c592af9d51ea0da78b1b",
    /* epk */
    "0e4237147546d913c2273bb3a70f6e3cbbd8b9f839c89cc1f8a26ecaa2aba986",
    /* enc */
    "d878f9142e82cfdcc5abb5f3d6b4b32978a6b8f3163cf48cd167abfb8512e352"
    "04e7edd316c39e5c9a01be0efab1707355bb93d9b968c50820f27b6bb20415a6"
    "0213dbf69f95554b56bac05cceae2f2f227b7c03925e87374fb1f9c3c0d723e8"
    "9fc80fa61c863fc04aa061c91cc81c484d086d2ab66125532d89a530ee6f07e6"
    "7941805f62784c8a8dec22a230506f9cb74e4c7dcaff00c4224543b052aa9f6b"
    "6db1837090f7fd87536d326866a8694dbe41b3b388cca38e6e546af80af68e9f"
    "8b24abb381fe57b6731dd686c179bea116a8e3be9fe041488d46634bda302abd"
    "027249fb2508bfc5260b286f0ab66a9c32c07fe1796c767b266d30d752e77840"
    "320ba9d7669c0ed9fe5b3c488856e84ab3674e4deed92225c4be2f31f56d4963"
    "b4bfc5f0fe686fc01950a9c5b6a95024086c566bfa7f1ce88fd6785660e60cbc"
    "0b2e881a4dacfdea6b9158717dd5d0aba72b30dd067f7c32b1e08f9a714a5965"
    "6567ea0fa3dbc31c12cdacbcefb9c42d832ae8cfea003fea36a32327f44ce8ac"
    "0d9aff4bccf03539cf037d5c2dfb114c2b027328660b0abbab07554015b9ab8d"
    "284db47c04b117e2a4365cd14f10c0416082d8615e36fa1bc5243c9d76902b99"
    "c87fb5d635b94157915fd979747247b5294006d2a74dce6c7c666e3d9c1bea5f"
    "b0124b846b22e217c6732817a13b72111395f496220af07bc8732e7d4a0f353c"
    "ff5b4c453915b5bee84ec00f817f51ff05d09138e7460727637641b178982a53"
    "3ca4618a251b2f92d7b73e5d31f3d56693964a014418d767dc23c6b522d2a695"
    "2a3d3200",
    /* out */
    "93148f0d468fa8c829f1499a4fa7acb16a99a2cd42b958397dffb46b2e34370e"
    "a2168063cfe245932eb4d828a461ad6a1f9951f2752b2ff9333893aa9045008a"
    "1b0bf265077c00d84d6617524e341439",
    /* recipient */
    "da973031634a8938ad1c480f978780693ec7709ba5caf58d8a7eb945586cbed6"
    "45520f17387437bcfdc216",
    /* rseed */
    "ab6fed1774ced71e695168fc591b9cfc196b7297ac0486db880fb455b1a0f3ee",
     /* value */ 0},
};

static const char kZcashTexStep1Sighash[] =
    "981da2d23dcdd6c04e5d36aa00cca4eb6d21cd4aa1af6547bacc5ab8d9764e7d";

static const char kZcashTexStep1OutputScript[] =
    "76a9142875b160968fae11ca7fdd0174825c812f24f05688ac";

static const uint64_t kZcashTexStep1OutputValue = 1010000;
static const uint64_t kZcashTexStep1Fee = 15000;
static const int64_t kZcashTexStep1ValueBalance = 1025000;

static const char kZcashTexEphemeralPubkey[] =
    "021dbfd8189e113def835a3f0eba3d41df5650f8391e37ab02b523ca567cdcadc1";

static const char kZcashTexStep2V6PrevoutTxid[] =
    "981da2d23dcdd6c04e5d36aa00cca4eb6d21cd4aa1af6547bacc5ab8d9764e7d";

static const char kZcashTexStep2V6Sighash[] =
    "03e328bb6a70c20bd803375f2da51bcd56d1e46fba7f6408752de160fc7234a5";

static const char kZcashTexStep2V5PrevoutTxid[] =
    "7d2c9e83172282b3d4521c9c16632bae0ef19dbaaa8188cb46761f510574b621";

static const char kZcashTexStep2V5Sighash[] =
    "89c5074214b150ff73a3d80fa893e1b66c41e96be1f67b504740a27b16a4f6e6";

static const uint64_t kZcashTexStep2InputValue = 1010000;
static const uint64_t kZcashTexStep2OutputValue = 1000000;
static const uint64_t kZcashTexStep2Fee = 10000;

static const char kZcashTexStep2OutputScript[] =
    "76a9148286bf790866805397e3a947640b77a43f0b43a588ac";

static const char kZcashTexAddress[] =
    "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte";

#endif
