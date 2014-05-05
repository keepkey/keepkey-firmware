#ifndef BITCOIN_H
#define BITCOIN_H

#include <string>

#include <crypto/public/crypto.h>

/**
 * Top level API for handling bitcoin workflows.
 */
namespace cd {

   /**
    * Default strength of the bip39 mnemonic.
    */
   const unsigned int MNEMONIC_STRENGTH = 128; 

   /**
    * Will generate a mnemonic that can then be used to generate a seed for use in 
    * generating further required crypto keys.  This currently follows the bip39 spec.
    *
    * @return a static string pointing to the mnemonic.  The string will get blown 
    *    away next time this function is called.
    *
    * @note The mnemonic is generated assuming a strength of 128 bits.
    */
   std::string make_mnemonic();

   bool sign_transaction();
};

#endif
