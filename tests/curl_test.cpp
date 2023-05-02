#include <curl/curl.h>
#include <dlfcn.h>
#include <gtest/gtest.h>
#include <openssl/engine.h>

using ::testing::Test;

TEST(CurlTest, LoadEngine) {

  std::cout << "Listing all supported engines, dynamic is required for now!\n";
  CURL *curl = curl_easy_init();
  if (curl) {
    CURLcode res;
    struct curl_slist *engines;
    res = curl_easy_getinfo(curl, CURLINFO_SSL_ENGINES, &engines);
    do {
      std::cout << "Engine: " << engines->data << std::endl;
      engines = engines->next;
    } while (engines != nullptr);

    if ((res == CURLE_OK)) {
      curl_slist_free_all(engines);
    }

    curl_easy_cleanup(curl);
  }
}

TEST(CurlTest, LoadDynamicEngine) {

  std::cout << "Try loading the libmbengine\n";
  CURL *curl = curl_easy_init();
  if (!curl) {
    FAIL();
  }

  // set the target website
  curl_easy_setopt(curl, CURLOPT_URL, "http://localhost");

  // enable TLS
  curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

  // set cert & private key for mTLS
  curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
  curl_easy_setopt(curl, CURLOPT_SSLCERT,
                   "nvpkcs11:object=CathiTlsCertificate");
  curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
  curl_easy_setopt(curl, CURLOPT_SSLKEY, "nvpkcs11:object=CathiTlsPrivateKey");

  // set cipher list
  curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST,
                   "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA256");

  // load engine
  if (curl_easy_setopt(curl, CURLOPT_SSLENGINE, "libmbengine") != CURLE_OK)
    FAIL();

  // use engine for all operations
  if (curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L) != CURLE_OK)
    FAIL();

  // enable EC for curl
  if (curl_easy_setopt(curl, CURLOPT_SSL_EC_CURVES, "secp384r1") !=
      CURLE_OK)
    FAIL();

  // perform call
  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    FAIL();

  curl_easy_cleanup(curl);
}
