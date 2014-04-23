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

   bool sign_transaction() {
      return false;
   }


}

