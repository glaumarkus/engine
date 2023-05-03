#include <cstring>
#include <curl/curl.h>
#include <dlfcn.h>
#include <gtest/gtest.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

/* check openssl.c in curl lib line 2584 */

using ::testing::Test;

TEST(CurlTest, FindDynamicEngine) {

  std::cout << "Listing all supported engines, dynamic is required for now!\n";
  CURL *curl = curl_easy_init();
  bool found_dynamic = false;
  if (curl) {
    CURLcode res;
    struct curl_slist *engines;
    res = curl_easy_getinfo(curl, CURLINFO_SSL_ENGINES, &engines);
    do {
      // compare memory
      const char name[] = "dynamic";
      int ok = memcmp(name, engines->data, sizeof(name));
      if (ok == 0)
        found_dynamic = true;
      std::cout << "Engine: " << engines->data << std::endl;
      engines = engines->next;
    } while (engines != nullptr);

    if ((res == CURLE_OK)) {
      curl_slist_free_all(engines);
    }

    curl_easy_cleanup(curl);
  }
  EXPECT_TRUE(found_dynamic);
}

TEST(CurlTest, ConnectionLocalhost) {
  CURL *curl = curl_easy_init();
  if (!curl) {
    FAIL();
  }

  std::string host("https://localhost:4433");
  std::string cainfo("/home/glaum/engine/keys/tls/client.pem");
  std::string cert("/home/glaum/engine/keys/tls/server.pem");
  std::string key("/home/glaum/engine/keys/tls/server.key");

  curl_easy_setopt(curl, CURLOPT_URL, host.c_str());
  curl_easy_setopt(curl, CURLOPT_CAINFO, cainfo.c_str());
  curl_easy_setopt(curl, CURLOPT_SSLCERT, cert.c_str());
  curl_easy_setopt(curl, CURLOPT_SSLKEY, key.c_str());

  // perform call
  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK && res != CURLE_UNSUPPORTED_PROTOCOL)
    FAIL();

  curl_easy_cleanup(curl);
}

TEST(CurlTest, SSLTest) { auto ctx = 0; }

TEST(CurlTest, LoadDynamicEngine) {

  std::string url = "https://localhost:8888";
  std::string ca_info = "/home/glaum/engine/keys/client.pem";
  std::string engine_name = "libmbengine";
  std::string cert_file = "/home/glaum/engine/keys/client.pem";
  std::string key_file = "/home/glaum/engine/keys/server.key";

  CURL *curl = curl_easy_init();
  if (!curl) {
    FAIL();
  }

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_CAINFO, ca_info.c_str());

  // load engine
  if (curl_easy_setopt(curl, CURLOPT_SSLENGINE, engine_name.c_str()) !=
      CURLE_OK)
    FAIL();
  if (curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L) != CURLE_OK)
    FAIL();

  if (curl_easy_setopt(curl, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_3))
    FAIL();

  // if(curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST,
  // "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"))
  //   FAIL();

  /* cert is stored PEM coded in file... */
  /* since PEM is default, we needn't set it for PEM */
  // curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
  // curl_easy_setopt(curl, CURLOPT_SSLCERT, cert_file.c_str());

  /* if we use a key stored in a crypto engine,
     we must set the key type to "ENG" */
  // curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");

  // /* set the private key (file or ID in engine) */
  // curl_easy_setopt(curl, CURLOPT_SSLKEY, key_file.c_str());

  // /* disconnect if we can't validate server's cert */
  // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

  // perform call
  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    FAIL();

  curl_easy_cleanup(curl);
}
