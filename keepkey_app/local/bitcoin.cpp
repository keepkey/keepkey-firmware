/**
 * @brief    Implements the top level bitcoin API.
 */

#include <crypto/public/crypto.h>

#include "bitcoin.h"

namespace cd {

   const char* make_mnemonic() {
       return  mnemonic_generate(MNEMONIC_STRENGTH);
   }

   bool make_wallet(const char* seed) {

      return false;
   }


   bool sign_transaction() {
      return false;
   }
}

