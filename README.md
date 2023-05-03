# Custom NvPKCS#11 OpenSSL Engine


## Description

This custom OpenSSL engine can be used to offload the supported cryptographic operations from the default OpenSSL implementation to this engine. This is required in any cases, where using the default Cryptoproviders on the adaptive stack cannot be used. This is true when using libcurl for establishing a HTTP session over TLS (HTTPS) that needs to be mutually authenticated (meaning that server and client both posses a certificate that is signed by a trusted CA) as well as the corresponding key. In the case of the Orin used for the IDC6, this private key shall be stored in the Platform Security Controller (HSM). In order to access this key for cryptographic operations, as well as offload the crypto jobs to the HSM this engine shall be used. An open source library that does this like libp11 proved not to be compatible with the way that Nvidia implemented the pkcs#11 interface, used to communicate to the HSM.

## Dependencies

- OpenSSL 1.1.1g
- libcurl 7.78.0
- SoftHSM2 (debug) or libnvpkcs11 and its friends (production)

The dependencies can be cloned and compiled with scripts/setup.sh:

```sh
./scripts/setup.sh
```

## Setup 

After setting up and compiling the dependencies (if necessary), the library will have to get compiled. 

```sh
mkdir build && cd build
cmake ..
make
```

Afterwards the compiled library "libmbengine.so" will have to be placed in the openssl folder that is responsible for loading of dynamic engines. On Linux distribution this location is: 

```sh
sudo cp libmbengine.so /usr/local/lib/engines-1.1 
```

Afterwards the included tests can be run to verify that everything works as intended. 

## What's included


```text
nvpkcs11engine/
├── scripts/
    ├── create_certs.py
    ├── setup.sh
    └── keygen.sh
├── engine/
    ├── mb_pkcs11_engine.h
    └── mb_pkcs11_engine.c
├── engine_impl/
    ├── src
        ├── asym/*              # load keys & certs, EC Method
        ├── ciphers/*           # sym ciphers
        ├── digests/*           # hashes
        ├── random/*            # random
        └── engine_factory.h    # interface to implementation
    ├── factory/*               # factory interface for implementation
    ├── unit_tests/*            # tests for implementations
    └── engine_link.h           # wrapper for mapping of functions to implementations
├── keys/
    └── <dummy keys and certs>
└── tests/
    ├── curl_test.cpp
    └── engine_test.cpp
```


The implementation for the engine has to be done in Standard C. In order to utilize functionality from other libs and C++ structures, all the implemented Engine methods will be processed in another library. The source code for the general Engine interface can be found under engine/*. A header and implementation file is provided. There is a preprocessor statement that can be activated in order to print each time the function is called. This is useful for debugging what interfaces other open source implementations like libcurl will actually use. The engine will support the following methods:
- RNG
- Sym. Ciphers: AES_256_CBC, AES_256_GCM, ChaCha20
- Digests: Sha256, Sha384
- Loading Private Key
- Loading Public Key
- Loading Certificate
- EC Crypto (Curve 25519)
    - Keygen
    - Derive
    - ECDSA Sign, Verify


The implementation of the engine functionality is completly abstracted to a factory interface located in engine_impl/factory/, where an interface between the engine and the implementation is provided. The actual implementations of this interface are then located under engine_impl/src/. Currently only software implementations utilizing OpenSSL functions is available for using. This will be exchanged with pkcs11 function calls to utilize the HSM. 

There are multiple other scripts available:
- create_certs.py: used for creation TLS dummy certs for testing connection
- keygen.sh: used for creation of dummy certs and keys for the unit tests

Apart from that and extensive test suite is included in the engine_impl as well as for the engine. The implemention code is tested under engine_impl/unit_tests/* where the code is tested in isolation. The usage through the engine is tested with tests/engine_test.cpp, where each of the usecases libcurl might utilize is tested against. Following functionality has been tested:
- ECDH
- ECDSA
- EC Keygen
- Sha256,Sha384
- AES_256_CBC,AES_256_GCM,ChaCha20
- Load PrivateKey, PublicKey, Certificate

## Usage with libcurl

To use the lib with curl for either MIC communication or dummy, the engine needs to be loaded in curl. Example is shown below. Currently using the ciphers in the engine is not possible without the hardware implementation (therefore commented out). Will get addressed in a future commit. Loading keys and certs however works just fine.

```c++
CURL *curl = curl_easy_init();

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
// if (curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L) != CURLE_OK)
//    FAIL();

// load cert with engine
curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
curl_easy_setopt(curl, CURLOPT_SSLCERT, cert.c_str());

// load pkey with engine
curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
curl_easy_setopt(curl, CURLOPT_SSLKEY, key.c_str());

// perform call
CURLcode res = curl_easy_perform(curl);
```