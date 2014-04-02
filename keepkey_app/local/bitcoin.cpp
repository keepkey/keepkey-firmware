/**
 * @brief    Implements the top level bitcoin API.
 */

#include <cstring>
#include <string>

#include <crypto/public/crypto.h>

#include "bitcoin.h"

namespace cd {

   std::string make_mnemonic() {
       return  mnemonic_generate(MNEMONIC_STRENGTH);
   }

   HDNode make_wallet(std::string &seed) {
      HDNode wallet;

      /*
       * The glories of inconsistent constness.
       */
      uint8_t *tmp_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));
      hdnode_from_seed(tmp_seed, seed.length(), &wallet);

      return wallet;
   }

   HDNode make_account_from_wallet(HDNode& wallet) {

   }

   bool sign_transaction() {
      return false;
   }


}

