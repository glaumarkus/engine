#include <iostream>
#include "engine_link.h"

EVP_PKEY* load_ec_key(const char* keyfile)
{
    FILE* fp = fopen(keyfile, "r");
    if (!fp) {
        printf("Error opening private key file\n");
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    EC_KEY* ec_key = nullptr;
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

EVP_PKEY* load_ec_key_public(const char* keyfile)
{
    FILE* fp = fopen(keyfile, "r");
    if (!fp) {
        printf("Error opening private key file\n");
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    EC_KEY* ec_key = nullptr;
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