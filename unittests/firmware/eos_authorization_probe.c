/* Compile the real implementation into the unit target, exposing only its
 * private authorization helpers. The production archive member is not pulled
 * because this object supplies the same public EOS system-action symbols. */
#include "../../lib/firmware/eos-contracts/eosio.system.c"

size_t test_eos_authorization_size(const EosAuthorization* auth) {
  return eos_hashAuthorization(NULL, auth);
}

bool test_eos_standard_authorization(const EosAuthorization* auth) {
  return isStandardAuthorization(auth);
}

bool test_eos_authorization_key_valid(const EosAuthorizationKey* key) {
  return eos_authorizationKeyValid(key);
}
