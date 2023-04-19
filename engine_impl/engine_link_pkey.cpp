#include "engine_link.h"
#include <iostream>

EVP_PKEY *load_private_key(const char *keyfile) {
  FILE *fp = fopen(keyfile, "r");
  if (!fp) {
    printf("Error opening private key file\n");
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

EVP_PKEY *load_public_key(const char *keyfile) {
  FILE *fp = fopen(keyfile, "r");
  if (!fp) {
    printf("Error opening private key file\n");
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

  if (!PEM_read_EC_PUBKEY(fp, &ec_key, nullptr, nullptr)) {
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

int load_certificate(ENGINE *engine, SSL *ssl, STACK_OF(X509_NAME) * ca_dn,
                     X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                     UI_METHOD *ui_method, void *callback_data) {

  // need to find out where the vars get introduced
  const char cert_path[] = "/home/glaum/engine/key/certificate.pem";

  // Load the certificate file into a BIO
  BIO *cert_bio = BIO_new_file(cert_path, "r");
  if (!cert_bio) {
    fprintf(stderr, "Error loading certificate file %s\n", cert_path);
    return NULL;
  }

  // Read the certificate from the BIO
  X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
  if (!cert) {
    fprintf(stderr, "Error reading certificate from BIO\n");
    BIO_free(cert_bio);
    return NULL;
  }

  // Free the BIO and return the certificate
  BIO_free(cert_bio);

  return 1;
}