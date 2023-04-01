#include <curl/curl.h>

int main()
{
    CURL* curl;
    CURLcode res;
    curl = curl_easy_init();
    if (curl)
    {
        // Set the URL to connect to
        curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

        // Enable SSL/TLS
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

        // Enable mTLS with PKCS11
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
        curl_easy_setopt(curl, CURLOPT_SSLCERT, "pkcs11:token=MyToken;object=MyCert");
        curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
        curl_easy_setopt(curl, CURLOPT_SSLKEY, "pkcs11:token=MyToken;object=MyKey");

        // Specify the cipher suite to use
        curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");

        // Load the PKCS11 engine at runtime
        curl_easy_setopt(curl, CURLOPT_ENGINE_LOAD, "pkcs11");

        // Specify the PKCS11 configuration options
        curl_easy_setopt(curl, CURLOPT_ENGINE_SETS, 1L);
        curl_easy_setopt(curl, CURLOPT_ENGINE_HEADER, "X-PKCS11-Module: /usr/lib/pkcs11/MyToken.so");
        curl_easy_setopt(curl, CURLOPT_ENGINE_HEADER, "X-PKCS11-User-PIN: 1234");

        // Use the PKCS11 engine for all crypto operations
        curl_easy_setopt(curl, CURLOPT_ENGINE_DEFAULT, 1L);

        // Perform the request
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));

        // Cleanup
        curl_easy_cleanup(curl);
    }
    return 0;
}
