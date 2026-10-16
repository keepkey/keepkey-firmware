/* A real NU6.3 Orchard bundle built by the orchard 0.16.0 crate
 * (Builder::new(BundleType::DEFAULT, BundleVersion::orchard_v3(),
 * Flags::CROSS_ADDRESS_DISABLED, anchor) then build_for_pczt) for the
 * "all x12" seed, account 0: one 100000-zat spend from the external address
 * at index 0 and a 90000-zat change output to the internal address at index
 * 0, fee 10000. With cross-address transfers disabled the builder pairs the
 * spend with a fabricated zero-valued output to the spent note's receiver
 * whose enc_ciphertext is random bytes (ZIP 326), and the change with a
 * fabricated zero-valued wallet spend. Flags byte 0x03. Both spends are
 * wallet-controlled (no dummy_sk), so the device signs both. Hex,
 * little-endian encodings as on the wire. */
#ifndef KEEPKEY_UNITTESTS_ZCASH_FABRICATED_VECTORS_H
#define KEEPKEY_UNITTESTS_ZCASH_FABRICATED_VECTORS_H

#include <stdint.h>

typedef struct {
  uint64_t spend_value;
  const char* nullifier; /* the spend's nf, the output note's rho */
  const char* rk;
  const char* alpha;
  const char* cv_net;
  const char* cmx;
  const char* epk;
  const char* enc; /* compact(52) || memo(512) || tag(16) */
  const char* out;
  const char* recipient; /* d(11) || pk_d(32) */
  uint64_t value;
  const char* rseed;
} ZcashFabricatedAction;

static const ZcashFabricatedAction kZcashFabricatedBundle[] = {
    {/* spend_value */ UINT64_C(100000),
     /* nullifier */
     "aed05ebddc392dda842311207fbc3fa84fb454f43fcfac292d87a3e8300ee112",
     /* rk */
     "2c1b8779ac1aca3abec73dfe9b8635be2fae970dfe76237495042fed96c3849f",
     /* alpha */
     "f081a5920a807a9189bc48f6ef5916b48effd77745c905def34316c2af87290c",
     /* cv_net */
     "e80cb524dfe437bebaaeffec6c4543a7f64f48fa4bfa03e1847641b184c3da1d",
     /* cmx */
     "6685ca96b57a11cae02c5c562b3f999713d06fadc697444e4c34f022a1df752a",
     /* epk */
     "e56229ea7072ff2dac9e9d0d3545bc13511e55b849089d3244e3d6667466872c",
     /* enc */
     "8807db653fc5d70f3382f580c2283ed388a87134aec35d3f1108efea6df55ef0"
     "b61eaa33b79f8d53b6a3fb791c83b75876186f6e404ca22e3246bd3d6ee956f6"
     "983d2f7efb6cbb27571832127afd4f48136bdab4ebc68bc2a7c667a4ab231030"
     "19ecd43212a1b6e47307949de23f82998fb33d3f3d15abefaa8052026b17d172"
     "1a508d8af11baa74df8f2f67c3be1a92bea530039b4920a0efedc8ee934485b2"
     "aecd88b5af781c8614d968236504d40d58d64875a808aae0995bb14577c89a26"
     "564f7be2d8a8e871ca8caaeb04c7af0023b25d6930745b0fce3d1b01575d68b9"
     "8965500c6de13f84b14052e24cca3bbe8aa0570ca4196b18a4b2cada1ddd039c"
     "4d6038c809426d1eed7674efb6990b040035cc1b92952dae4d642f9c4c613572"
     "59dc961c5f208a14387b7d8f9b4f5e502a09aa1d292d33e72b489bb5e5cf4ede"
     "7e239d96d07139f9270ec5a3305da1013f0a5b6de6860af11a212c77fe5c1cb9"
     "73888cbc1100e0e07423e879e40365844c2ca9a75b16ed4d032127470ca0e0bd"
     "5de907a32b3aea36512929f5b83863bc1d63b40fce26dc4d58472ec15f2fadd2"
     "24c16985bd5ab01e388502dd22596fe85012a9f74e2ea6c9b9aca2b7bc2298ed"
     "779c61285753e6ba92f0a1a963f33750c105122c7e5ec92d95e2f454e0556682"
     "25ebf956231f22a139c3c31fdb7e4a4a214d296765353e0e45269cef2eebdbf7"
     "e53e3743c4266eb705d30ea2cb567e370eda979b44f33ee2f6233dc8e1f5e844"
     "ff66891d37165675e63b2a10722381a55a92b006dd793ca832010a002d3021ab"
     "5e526af9",
     /* out */
     "a5fe4a96ac820c57db11db73741c6fee879c90635e16c5fd60967be70c58f27d"
     "85e4a135ac87ecc858d88b34df846b2af6035683c138b97876c373328076e8ce"
     "f61c5989e4fee41ed2334b932f947f82",
     /* recipient */
     "da973031634a8938ad1c480f978780693ec7709ba5caf58d8a7eb945586cbed6"
     "45520f17387437bcfdc216",
     /* value */ UINT64_C(0),
     /* rseed */
     "c29d5ab216448f6ebf6388a6251160e7c9fe2413c85ac1cd2340363807ba8840"},
    {/* spend_value */ UINT64_C(0),
     /* nullifier */
     "31aafc80063db2af87ffdee21267ccd1f8a6eda982f7c5816b8f1d99ee580217",
     /* rk */
     "defbdcf42d021aa013d14a391b3cefa8ce94ac9cac96481bfddecab3f2065e06",
     /* alpha */
     "a16c066adf9a10e1696c4fa884a67f93b24d858e8cf06743304ad6cae69a1b06",
     /* cv_net */
     "fd260057cb02e71c9d37554c7fb496b48d5412c1c2707fcf0c8601946dd04c12",
     /* cmx */
     "e35568cf21a2befafa3d8bbd2bf6a19bcdbfe6b6234c303004ba38ba76afed3f",
     /* epk */
     "9b9efea983df2470cfc8d28bcf8c5bfd4f714e6bc08b0a15ab3611b0c7b56101",
     /* enc */
     "b82f1b13e501868055a3f88433481172ee1173402227637b46be3e63cd3fa939"
     "93af3074450b558a4d6ff8ee65bdb04962077060b5c258b3d0f7bc21ec7df69a"
     "a0898c47b6d913186a13fa21c420f0da48e72d167bc3e08bffa1f16d99a11aad"
     "65cf98cc0a0ce37ec679c03dc7c6f1fe9feb619b4eca0c5823f6d413c7a5be12"
     "2aee48f070770d163fde8ad4862df692d4433afe053e6b9e1a50e6cc8cbd37aa"
     "54ce3e014e3dd342496855226cd65896442300161e242a8c4d7b2c19c83df04f"
     "f3ab7c7afcb9fb486d28bda503260b758ac473b618cce25b9d0daf8bafbe64ee"
     "3d52f804c33ee78e25fe5bd6a105d4a1cde143e2d047f0fee8e9cb3645964688"
     "2eb5ade60a1ff79284b81ee817d638ad5e1da8052266171b320a8bf4ec337df3"
     "ebcf087de768b46404f45a23208c8358c644e626152d67cf4e2efa94ff9ac2dd"
     "b8e3c670360523c238f1cc3b961dedade8e90de90927841745c5398f140ac053"
     "8d48561bb372a367933147d239c500c238cf294d05e93c473378f59708f5aefb"
     "375d23df2d0fc1a8f0de90c8fdb6cbb0036eef778c1bdca2731c7fe23a0331ee"
     "4ceb357a52ce552ca0626891f5362c1983fb2656f91b372f0559de8943a9e555"
     "30bc009ede7c222f8748ade9762270f937725a25401ad5a4fdc01a3f1f100289"
     "c5a291b9bfc3bc696e0af71e7199f6555b53ed875aa7ebdfeba1cd3f8c711190"
     "c6d5c64059483983834faf47283ca15682c4966070425d0f305cad882901d70f"
     "d222a8bfeb2077541449b73ce56a8d08aa623c06aa8b38e675eb17fd162b862d"
     "5f777396",
     /* out */
     "28c960f201269936a006ae1cc2cd358b29f981dc52d10448a3c02479855bf89c"
     "ff2a654493f29035ff20daf3ce97d13d514bca41d0d298d0c40834248d1f617f"
     "3db9516428eeca01be53af1da897071e",
     /* recipient */
     "ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0"
     "f0bb27c032b2e7718c962e",
     /* value */ UINT64_C(90000),
     /* rseed */
     "c53e0dc6ce5562fbf35fd57698514207df3cb42161093b070ba16bffcb93fdd9"},
};

/* The same spend and change built as an NU6.2 bundle
 * (BundleVersion::orchard_v2(), Flags::ENABLED), as wallets build today.
 * Action 0 holds the spend and the change; the builder pads the bundle with
 * a dummy spend (dummy_sk, signed by the host) and a dummy zero-valued output
 * to a random address whose ciphertext is a real encryption of its note
 * (protocol spec 4.8.3). */
static const ZcashFabricatedAction kZcashPaddingBundle[] = {
    {/* spend_value */ UINT64_C(100000),
     /* nullifier */
     "aed05ebddc392dda842311207fbc3fa84fb454f43fcfac292d87a3e8300ee112",
     /* rk */
     "2c1b8779ac1aca3abec73dfe9b8635be2fae970dfe76237495042fed96c3849f",
     /* alpha */
     "f081a5920a807a9189bc48f6ef5916b48effd77745c905def34316c2af87290c",
     /* cv_net */
     "ba35dd670b2f19d39a44f2fb871e35ec8b9a444d49bf84a8e9bf6c5556e69d0c",
     /* cmx */
     "087796ff6b2f7943ea69464410a8b2710c2b90316fd5c748f41e3a4793b59d0a",
     /* epk */
     "81f9bbeaf78f326630fd4526ab67289a44d0d09972ef30682d4f5ffeb9417798",
     /* enc */
     "7635af9d8406383ee8dd92f37ef87a8216b57a8004ea779251263d8665916e2c"
     "ad6139ad2266484d70f79806e431c7531de4c5d620b14b585070871e1c50aeca"
     "dda4ae9a45216132c33e3ec304c1edaa29d1a18687e546b95139bce8f57de0f1"
     "1e200bad146f9580434d6471084df7b0cb8b54f09098923e821939c6769f33f4"
     "1add1d82c3660dcf065c8bf43e3f69925270ef175fa2f595166dbeeb00d2eed8"
     "d19280580081a541ff0db45894f0af53c82f85c4d83e139a98dd99b5544ab23a"
     "0ee74c33a416bc4ab28d28d5717463f9e100f7cbe2f7334d93a6f8715e49791f"
     "3e1efb1a6c285b9e9aaca988ea3d4dd90ec5307a7e8067d7926bbc664c049968"
     "aac677fd0497c68555809c7f34888b5aae50ba8c4bc509a1a5773eecfaf57e32"
     "7bbcc042059d61e60c37bbe6b9981f8c862c08714ced7143e480d33373bc2871"
     "0a6cc670f85d68400fc49e5581b2a918bdac988ec720a9fc2196a0833db5026e"
     "753924001effd0ca209bdf8fab61c4cbb8e666d408979ad351f9de8e3551a032"
     "a471b1842cb2534c8f98996d964b67344a96f5baa24db77ebc581a252d242933"
     "d413c4cfe3dc9b60b7821d4f02d95a09321cbd677e9311f0acfb6e2e97d54ca7"
     "3280e64c2d216e3b190a44b5b6c26da1a9f8ec1dac3d5d494e4c650562ad5594"
     "6736bb8ea447b4905a1602a67c988c5aba1fa81c03e33b1af82f60de2c23d1ac"
     "afcd6dcfb1dddbe12b695295a694e893f2279a271039ba3eb1ab48446047bef2"
     "9efa519bb08cb6f0c0a753f9a70c2b683e55b783a8a79310e990cb9fbef3d1fa"
     "255602bc",
     /* out */
     "72d9526061fc8f2088c225996dde720ab8f19502950b052f9c8d9e8e00f06532"
     "ba4ffff2ecd176e5836af72a44a1d58cefd03dd089b66b4dc0d92d3860e1d437"
     "5595655e7abbb43afcea3a8b570f1987",
     /* recipient */
     "ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0"
     "f0bb27c032b2e7718c962e",
     /* value */ UINT64_C(90000),
     /* rseed */
     "c29d5ab216448f6ebf6388a6251160e7c9fe2413c85ac1cd2340363807ba8840"},
    {/* spend_value */ UINT64_C(0),
     /* nullifier */
     "82b4ace6f48bca884543cca25633e137f3791e3ed655c775f8b6f84187c8082d",
     /* rk */
     "ffc4c2218a0382a530909566f44a7ab4421df95cd12e0590a19c01eb6e06b83e",
     /* alpha */
     "14de74940160f3450f3f8fad83c3d50dc9fc766bcdd4d5968a13ad8245613138",
     /* cv_net */
     "21f87ec22c92674f97585415535b5cdade848408fb729765bdcf2c36118e463f",
     /* cmx */
     "b46b4f684d39569dcd24db0db912406dff3fbc78466e590260d729313499230d",
     /* epk */
     "a7d08787142ac449a74203ccf11ad1e927b8fb4356f33ae8f81b1c9e7b3c01a6",
     /* enc */
     "43fed1e4afbd93923651a18623245c91b2717cbbf89ef9a4905bd0da58f3a578"
     "bd2330a347bc32526261273feeb11120746ce964aac12d82209183195eeafa8d"
     "54ac7b02e4c107aee4ec1db2452a50bcf53ebb7902827bfef0ba144ca16c0f9a"
     "1ef79116b5f86a740a68c46b28f5b1235235ed347244ff7beb65898e74f139d5"
     "975965a2f786e60a9b081f96f576a087070bb7a8e1a182fbf7366467005a051e"
     "28ed1509aa2177a684417e618e0a07a4f157f1152308ef7f6757533f5f45cd67"
     "a21cb1b26944fb266fd2bd6e892bc9bc672d2eed09afcd7119074b0c8639b13c"
     "548df077595390a7aa4b4181341804c793644d9bd19b92e0e322d87b64075eac"
     "7e6a908c9fee485175ec7c85ffd3e010a85fb67adf6435bd66f45464f7ace727"
     "7471eed60135e19d420fb5b9af89957b23f33e458e09c393a02d9403eabef6c8"
     "f11f4002cd2c877197f573bc0146bd6eef0bc00283f29ad0ae500ea80c84e221"
     "81f9470a4d1e8c60b4680efbd5dd47fa73cf82de930b304afe0686d11b963c8b"
     "e5a3731e7f74b245958c46c3e0b591278ec8e4206f291a80193ec325f06742ee"
     "3de56bd11121df9432eb2456ae090f64e840d2ea17365abb6c6ec9fd51f94036"
     "c0ace903ae39ef5a0824799b1b4ba529c3403d240d7f18cb90559af4252f1fd2"
     "27eefabfcb830b94c3c3e5114e41265cef100aad103bd25505279a39cb294db4"
     "0ccfe4d4b8c13539b975564008c113da36d67d50568769751fb9c775f363c969"
     "4d834ba1ea03e956a6036dc2a676918044a1fc76c777caad479de213ef856055"
     "5407b7ca",
     /* out */
     "e41a17506e1af63acd8edc563c195819e26e740b5f3fb4830242d804bcee8a56"
     "2572f52e73d190ef270ecf7aaf309e93b2ab9eb6200b8466cd1aa7889b42cfcc"
     "2fa9b853f9e136be5e04f9020ac82d4f",
     /* recipient */
     "df8789f215ca59a4fc59ce4e9b694f87b354d01cc397c47b594db69dc0fd4ad0"
     "0e11a41d7751189db93210",
     /* value */ UINT64_C(0),
     /* rseed */
     "983d2f7efb6cbb27571832127afd4f48136bdab4ebc68bc2a7c667a4ab231030"},
};


/* An NU6.2 bundle (BundleVersion::orchard_v2(), Flags::ENABLED) built the
 * same way, spending one 100000-zat note from the external address at index
 * 0, fee 10000. Its four outputs, in action order:
 *   0: 20000 zat to this account's own external address 0 (a self-send);
 *   1: 30000 zat to account 1's internal address 0 (another account's change);
 *   2: 40000 zat change to this account's internal address 0;
 *   3: a zero-valued send to account 1's external address 0 whose memo reads
 *      "thanks for lunch!".
 * Only action 0 spends a real note; the other spends are dummies (dummy_sk). */
static const ZcashFabricatedAction kZcashMemoBundle[] = {
    {/* spend_value */ UINT64_C(100000),
     /* nullifier */
     "0b396499eafbba166a936684287c6a9a93c35684059661a365e715c6bdb80903",
     /* rk */
     "0a1d22eb81961326e4d6c5dc1208f1e166cde2d52d7a4ab65b26c74d6281cd0f",
     /* alpha */
     "3b977876ce497d64ec92c71e7e8c0ba25c6e831636d6f0942b7cb944cec18f35",
     /* cv_net */
     "bd26a17d837f604b0834a4f6c4e0b04128d72b98d0d783ff6ad7087feb2e4d10",
     /* cmx */
     "9e926d6a1e046c426c00e41c618e42040dbcb8a4122aeaec30a1558b56e3cb3d",
     /* epk */
     "5d8fe257f17e600c74f9ba9bcc221c85c7074e1ef6adaf23ad884bdb52eea72a",
     /* enc */
     "8b0075c256cacbebdf9dcf8db1c780c3149e9130d03fd8b509201130604d5848"
     "ac64ec54a133fb72f09083efedd825a3b08f5f7bf5f54a85a2390ab2e37eaad0"
     "28a3a245ce7279f4afe13e5ade9e6eda947119b68ebdc9f86fff852cbe1f0217"
     "d4119815506d9bf3e4530c80c357e0a4910392d59b4d531ff6c318de528fb6b0"
     "5fae9aee00fcfe88661ca4b181a96b4255a0a81ad38f21f629e47bbefe5efd1d"
     "829d93542f4d6f6fc8e9cc9a5ae91adeeb657c0b3427a86654ee502c944ba189"
     "95d9bb4d40de6fbf581d4a89e407e27a968cc0c168ae7f3dcf5afe3272f1dd0d"
     "d805f01b367d93ffd8557e69d39957540e1e70e8cacb7d7a844ff234bc49c403"
     "1f39598fcd696606eacbb267172c90f5b438dd4652e6f2ac83913bce4ca7d2ef"
     "d1d04a4fa7eb66f8342bc2b84ff03e64c21139de5c6dc257518c0d20f48c705e"
     "512a474d25185e54187af3d650b56ad12539b7797550bb117d12ac6d6ee9c691"
     "684fd3c86bbfa004484d6f08574f0bb4031aa27e0599e15f8ce2b00711281f85"
     "cb92e63fb66d0794e4dee0ce15b7e0c3851266ba8c49c9cf2abd22a488e95578"
     "693a9c0d5e27ca808de4fc81cafeadbbbff7f83dbc4debba908510279941613c"
     "f9ee909eb5b922b2333f48422cd0bceb61625d21c6b3107cb676e60ad681c4a1"
     "51c1b24734ed1f3ec096785c45641fdad75697abdf66e9553ec51af468f90ec8"
     "aeec7cc04e1f6c03656da3389a4fdb287bde0e01bfde5f125803f604a5f38d12"
     "482155475a651f76c56eff1777403c5a48499cb196fe7bb0c98e59af720c6090"
     "48939155",
     /* out */
     "93d14b5a4bc9dd72c1559c0073dd621c184af991a87c75215fecc816f20b83bf"
     "3673bab907166ef00ac8b8f67b2be681ebec1b8f49ea0918a0796bbe4ae02925"
     "8a6fec6129eb71fc611a7944b9625b7f",
     /* recipient */
     "da973031634a8938ad1c480f978780693ec7709ba5caf58d8a7eb945586cbed6"
     "45520f17387437bcfdc216",
     /* value */ UINT64_C(20000),
     /* rseed */
     "19d1dbfb752c1bbc9ec9a5c44fd2d8a9d79c404e299127d3ad5f34a2b52f4a94"},
    {/* spend_value */ UINT64_C(0),
     /* nullifier */
     "f8ba50efc52be70daca605a52065c1f1f58feeff3fdb41ce608a18e529326905",
     /* rk */
     "7282993aed2a09e3d374bc473dd16ec6a760fd8a667b3cb32521f50b80fc3928",
     /* alpha */
     "1cb2601e62e5bf33186b33ea9acbe76d31509cc5e5826ab7b549189b55cc903f",
     /* cv_net */
     "34fd5c6923a81270493d8d8e517044305f7595217d8e3bea2f473b35b0a78017",
     /* cmx */
     "9b020d8c509de25cb2c04955725669284951e081ca602d27b6986f4c0349e93e",
     /* epk */
     "85f4e893d37fbbee4ea43e7cb447c38d1f31669930f8d800e39d3fcac48ae3a9",
     /* enc */
     "54d68d62720be92d6c4697751bde5ab39c3de61aaafab88161765cf4aa27a151"
     "b0f5be29d7fcc7f30c6a9301cbfbc4dc348a30a8821fe56c73c8e9c799cf9f50"
     "64f8c5778a218123bcacd4b43d971d2a96452a69de0c48b3d9b6cb7a11967851"
     "04c7077ae08d0be113696c6f34c41f339c5cee68611856f627553f41e511ff43"
     "90a80c74fc31dcc4d1a10b8bc02706ecd187d02aef6fc39f166815c7a12afd39"
     "b6fbde42959672fb508df5432848e5061acf62263046784e3f252a57604f4d3c"
     "c8a295e5bacbaab6f4b0f5aa7b3790abf576260b7d40da6266818f22b4e75a53"
     "1b6e565a87ceb0f2a01d70c764de4545c4d5707394af31752b2c30f0fcfd64c3"
     "5102558160449a78e3887053d63f015650dcc7f1f56114739bd6f1e730eaf0d8"
     "e2a5755c3424ba6b205145ded3620702c853226945fd8dfddffb359016c24784"
     "c8ce7edac0f02345f6240b4a055b712777f344e4f176082ec27e07ada09473cc"
     "7868836a98f7f1de99cade6bb9c1daa9e54c591202f83e90eee76054e76b45e9"
     "89caac1005cc961af5111a46c11a41311f6e94540e67f2005d618e731d4792f0"
     "5b31ef94ed6d73216991c1ffbd0645bfeafb64554ad082fad7286af5e88ca721"
     "ebb6e89a8aaa097c33c3d3c00b645a5b6e9d892417624d9b58e5157c4f9406e7"
     "ec81cd89028d8969f54feffb4825017676044d5e3ae6603f058f772953c714b1"
     "1ed1523d2aa37d36f51bec1a36268bb0953f6836534df86ab196929d5b916781"
     "071680fb04d6d27f38399a952bcdb7a459f4fb74d5dfd73c6a0a51c58ea00a53"
     "bc4fb482",
     /* out */
     "b95c75498fd39fe8ffb67803469bb183e6746b7126550c0d56f248d5a3bb2485"
     "19ffbac31035d28a29b5295e929bc026f8f321bab87245f47ad4c4604bdd6efe"
     "4f77fcbe2fdaa78a5ebd58263a7f6d0e",
     /* recipient */
     "e96953bda73d114cb7bc026036b695c23fb2b80b0c34f217ed3b4e6fd3766efc"
     "090a17663191a15eba81ba",
     /* value */ UINT64_C(30000),
     /* rseed */
     "b7a8c118ceb43470d6a78bcb0eabecdf96b3977bb99506442df3c1db52a0b58c"},
    {/* spend_value */ UINT64_C(0),
     /* nullifier */
     "a75bf6e26992c5a04856020a69caa517ba5b0f6dc026e8e8713ae606f2be330e",
     /* rk */
     "b0aba46130d9dfa7e5a1260d134958d5caefed021551c1832fe07cea52ade4ba",
     /* alpha */
     "a16c4408414428dc4e614b56f9bcb7bff36ed395ff25f556327ed877556fef3d",
     /* cv_net */
     "7cc907eea8e6bb1eec198132f122fb9ff7f0797df56fecf63b7d2f2e4fd283b3",
     /* cmx */
     "15c4fafb44b3aa5ef021ec25208136a785139f61a2dc69c1bfa2280e7dc46f08",
     /* epk */
     "34737234bf9190c4a909a96b58f66843fc1ae968851d9dcfe8b9d8a0b1b8042f",
     /* enc */
     "d2c52957269904d95aad1058335d2b431d46e3702b28496752c5d07fb5fdac1f"
     "bbb6e798057939f1b732416f0717f72a037402e6cb6c520c785f87c5eea9655a"
     "654936d982329d9f637998e6909b947ede5f3c0844c72d291607bc2dfc0d37e0"
     "1e32cb8637244aa02c33ffb95e9b9b99e2936614cc8c95bed046b44fe18c2aad"
     "bb2dfa950de507fd49774343f24ae5329904e7e4b526769a7c3dcebb473d2224"
     "76c480d96335b9f3be0e8ae62137d43dc508c7dbe44cd402514aabc2fa8fa81f"
     "cec38e74aefe8ad0defbcdccb091b50b27c0f2abd5622f3cf9d6a0272b7700fe"
     "df22cdcd208c0b6eb94f7ecacbf6af61be4d581efae66b30b7b39d3806ec247c"
     "4e16282839725d0eb0836f26500552c7bd98795325888f8626f0214eaf429c6a"
     "55cfd7fc564e468103fc577bcf69a5d9f64894262d80731629977972ccf9c962"
     "871720149b9db9e4088f061ccae62619827e31b7ae7a7d878bc51b9d63e73613"
     "dd0352e4dffc62fbcf6435b72ff1c2460bf9c5609db734a59ab3a274e0de8dd5"
     "2002f787135b9120c02947e62c0fdc4d633248f0098cafecfc8b5ff165392292"
     "205c68d13f6e8bc261b6863770c1fdf9715ab0553f8cacf07b20146f815af9a3"
     "6664e90df7bacb0ad412e4cd363cbb2a0936d89afd5a228687f9b192b4043a54"
     "1341ab18a82405a57e24986d227d8e5c285c0708843adbf2a29293d30e4e9b61"
     "ceddff354e24427e6d2a34cbc1bc6057ec6748387305ecb9ca7b70926e672104"
     "900779a167ff00024e3cc6e1cf05636eb7cfb34a2c289bab49f411a9cee2701f"
     "d44d2d13",
     /* out */
     "8e6250a506ea4b52188f10ac0ee0e0210ced8f7f8ccda7069f70ed8ed675a953"
     "cae9a37666f191921050a3da74636c907e3c7c36a75ec459255c9ed828718a8c"
     "b31e6ffeb3946f1fbcee60568ccceffe",
     /* recipient */
     "ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0"
     "f0bb27c032b2e7718c962e",
     /* value */ UINT64_C(40000),
     /* rseed */
     "2a6913ff3dcb6d496a92b8d5cfccd29afba7b48fc1e21940b55739c5ff950d6d"},
    {/* spend_value */ UINT64_C(0),
     /* nullifier */
     "9c8426bcbc3202267606069136500c06aa2e40c378ba22a898aeff0626c75036",
     /* rk */
     "9e74449a938707718574712d19923a0a48820aa17f53491007f873fc3f902902",
     /* alpha */
     "a6e1c02c22a34f14a0a82c221489f26136081ed39b3ef34ac2df17c08aa2e235",
     /* cv_net */
     "15fb882089e16d2f696b2964c8d13fcfbbe66a1e645bf08afdfef2a15352a3a4",
     /* cmx */
     "5d491d6e064e67343e179ee680182a04eca8a9c73b504e17439f695b989d8d35",
     /* epk */
     "266dcf5ffab1cadd4fbc6f030b702f535c49b0971c79f6d581491b5e727eb797",
     /* enc */
     "8c7b608859f1c6b4a1b3e304f9ac0319680d53950d98ad1e36216abf62870bc8"
     "69195aae61e811cc559a3a06df605489027763cc10731e262dc477c40589c9ac"
     "6350ead8f31d6f37d8eb698c7afdb8f835b108d554e97753a8838fb47f0fc1cd"
     "989ed1190517a4f455267458b8c9329f846bed3993db930520ab71ade3e5256d"
     "ac93ebdb7abff16cf88030df72fa90db30d3745480c914d501579a6ab93b8472"
     "a52137f13917657037fc458546a1e41af7f12d8b5b492e69c9d595d4e886627c"
     "6656b5a3ee37ebc3689290bc88707c91e026d95859d88c5e2187339e4b3e6bff"
     "924a0934468e64b86dec35b26c6d2cb750d13f21101e1992cf64eae8547ab462"
     "9ad4c7e88264c4a2f04adcbd2cd050038239498b306572494920bdfc7a1bbee9"
     "b190ba82f88e670d7c690b069bfd073c9c4222da760bd347c4e4d321fcddc057"
     "88114a34b9bf3b4054381c8595c7ec80140968741d55f1939a9121b3369afaef"
     "4c5ce10e662e13b2c0ecd8deb4469a92b66ee8ec2ddc0c600700f1e39cfca631"
     "fef6920a7af021715fe51c178b1665c5d0a261dbcc5ad171613402ff29d883f5"
     "12f8a488d23bd4401781997e4dc0d7b62b8bb66f64ace822c08177544dab0a46"
     "930ab73eb589460e9e19a77eed8f0a494b92f41dc1dc70572548e755a2023444"
     "9ec6d30af18d58d1f0a2752bb8d8a4d201232d3bb3ec3d6fe3fff3cbbcc7e350"
     "e65808cb45bd1d367e447b728ac6a1445a6c7bae6eece7e2b3ecaab583a9ca58"
     "e41cca24d08366be4516fea9dbce82e4de6845b268708b96a572d619e808bb11"
     "06ae8a55",
     /* out */
     "eacafd6869e89e8312a0a7caff1e8baf61be383e17db1e61017eaa5842091a05"
     "ec776f4b7fdf85b1f90aa0197118d355ed1f73ac5795f8296afc5f4b87916b2a"
     "7cad4d62b2f8c75acafec1ed5bc5248d",
     /* recipient */
     "8ee82cdff5120a00cb089ff8acdaa517958971d69d1852dca01fd25e88609ff9"
     "ca7b154dcb2c01a8bc18aa",
     /* value */ UINT64_C(0),
     /* rseed */
     "337ce21a2c63debee0bfed8ad8c373d7d5f3fbfd44bed30f2addd92130ef5605"},
};

/* Mainnet Orchard-only Unified Address of action 3's receiver, encoded by
 * zcash_address 0.13.0: the address the user entered for the memo. */
static const char kZcashMemoUserAddress[] =
    "u1u2e4d2ctdr0sq2rtglp3myfzpewgtslzjss0p4jtldylakd8dm5n9rtflehnykkq6c0g5rf"
    "zrswl5tx02uzulwa4xqdpmm9pnuuslzs8";

#endif
