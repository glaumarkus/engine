#include "engine_link.h"

int ec_verify_sig(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig,
                  EC_KEY *eckey) {
  return 1;
}
int ec_verify(int type, const unsigned char *dgst, int dgst_len,
              const unsigned char *sigbuf, int sig_len, EC_KEY *eckey) {
  return 1;
}
ECDSA_SIG *ec_sign_sig(const unsigned char *dgst, int dgst_len,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *eckey) {
  return nullptr;
}
int ec_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp) {
  return 1;
}
int ec_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
            unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r,
            EC_KEY *eckey) {
  return 1;
}
int ec_copy(EC_KEY *dest, const EC_KEY *src) { return 1; }
int ec_set_public(EC_KEY *key, const EC_POINT *pub_key) { return 1; }
int ec_set_private(EC_KEY *key, const BIGNUM *priv_key) { return 1; }
int ec_set_group(EC_KEY *key, const EC_GROUP *grp) { return 1; }
void ec_finish(EC_KEY *key) {}
int ec_init(EC_KEY *key) { return 1; }
int ec_keygen(EC_KEY *key) { return 1; }
int ec_compute_key(unsigned char **psec, size_t *pseclen,
                   const EC_POINT *pub_key, const EC_KEY *ecdh) {
  return 1;
}
