#include <cstring>
#include <curl/curl.h>
#include <dlfcn.h>
#include <gtest/gtest.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>


/*
need to run openssl s_server outside this program to debug:
in keys/tls:
openssl s_server -Verify 1 -cert server.pem -key server.key -tls1_3 localhost:4433 -HTTP -www
*/

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

TEST(CurlTest, LoadDynamicEngine) {

  CURL *curl = curl_easy_init();
  if (!curl) {
    FAIL();
  }

  std::string host("https://localhost:4433");
  std::string cainfo("/home/glaum/engine/keys/tls/client.pem");
  std::string cert("/home/glaum/engine/keys/tls/server.pem");
  std::string key("/home/glaum/engine/keys/tls/server.key");
  std::string engine_name("libmbengine");

  curl_easy_setopt(curl, CURLOPT_URL, host.c_str());
  curl_easy_setopt(curl, CURLOPT_CAINFO, cainfo.c_str());
  
  // load engine
  if (curl_easy_setopt(curl, CURLOPT_SSLENGINE, engine_name.c_str()) !=
      CURLE_OK)
    FAIL();
  
  // set as default for crypto // incompatible right now
  if (curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L) != CURLE_OK)
    FAIL();
  
  // load cert with engine
  curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
  curl_easy_setopt(curl, CURLOPT_SSLCERT, cert.c_str());
  
  // load pkey with engine
  curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
  curl_easy_setopt(curl, CURLOPT_SSLKEY, key.c_str());

  // perform call
  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK && res != CURLE_UNSUPPORTED_PROTOCOL)
    FAIL();

  curl_easy_cleanup(curl);
}
