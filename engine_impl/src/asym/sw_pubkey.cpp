#include "sw_pubkey.hpp"

#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

namespace Factory {
namespace SoftwareImpl {

// the key_id is expected to be an absolute path
EVP_PKEY *SwPubKey::Load(const char *key_id) noexcept  {
FILE *fp = fopen(key_id, "r");
  if (!fp) {
    printf("Error opening private key file\n");
    return nullptr;
  }

  EVP_PKEY *pubkey = nullptr;
  EC_KEY *ec_key = nullptr;
  ec_key = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);

  if (!ec_key) {
    printf("Error creating EC_KEY object\n");
    fclose(fp);
    return nullptr;
  }

  if (!PEM_read_EC_PUBKEY(fp, &ec_key, nullptr, nullptr)) {
    printf("Error reading public key from file\n");
    EC_KEY_free(ec_key);
    fclose(fp);
    return nullptr;
  }

  pubkey = EVP_PKEY_new();
  if (!pubkey) {
    printf("Error creating EVP_PKEY object\n");
    EC_KEY_free(ec_key);
    fclose(fp);
    return nullptr;
  }

  if (!EVP_PKEY_set1_EC_KEY(pubkey, ec_key)) {
    printf("Error setting EC private key to EVP_PKEY object\n");
    EVP_PKEY_free(pubkey);
    EC_KEY_free(ec_key);
    fclose(fp);
    return nullptr;
  }

  fclose(fp);
  EC_KEY_free(ec_key);

  return pubkey;

}



} // namespace SoftwareImpl
} // namespace Factory
