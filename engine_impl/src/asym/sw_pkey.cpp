#include "sw_pkey.hpp"

#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

namespace Factory {
namespace SoftwareImpl {

// the key_id is expected to be an absolute path
EVP_PKEY *SwPrivKey::Load(const char *key_id) noexcept  {

  FILE *fp = fopen(key_id, "r");
  if (!fp) {
    printf("Couldnt load file pointer\n");
    return nullptr;
  }

  EVP_PKEY *pkey = nullptr;
  EC_KEY *ec_key = nullptr;
  ec_key = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);

  if (!ec_key) {
    printf("Error creating EC_KEY object\n");
    fclose(fp);
    return nullptr;
  }

  if (!PEM_read_ECPrivateKey(fp, &ec_key, nullptr, nullptr)) {
    printf("Error reading private key from file\n");
    EC_KEY_free(ec_key);
    fclose(fp);
    return nullptr;
  }

  pkey = EVP_PKEY_new();
  if (!pkey) {
    printf("Error creating EVP_PKEY object\n");
    EC_KEY_free(ec_key);
    fclose(fp);
    return nullptr;
  }

  if (!EVP_PKEY_set1_EC_KEY(pkey, ec_key)) {
    printf("Error setting EC private key to EVP_PKEY object\n");
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    fclose(fp);
    return nullptr;
  }

  fclose(fp);
  EC_KEY_free(ec_key);

  return pkey;
}



} // namespace SoftwareImpl
} // namespace Factory
