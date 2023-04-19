#!/bin/bash
openssl engine -t -c `pwd`/build/libmyengine.so

openssl engine dynamic \
          -pre SO_PATH:~/engine/build/libmbengine.so \
          -pre ID:MB_PKCS11_ENGINE 