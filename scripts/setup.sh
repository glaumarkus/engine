#!/bin/bash

# build openssl
cd deps
wget https://ftp.openssl.org/source/old/1.1.1/openssl-1.1.1g.tar.gz
tar -xzf openssl-1.1.1g.tar.gz
rm -rf openssl-1.1.1g.tar.gz 
cd openssl-1.1.1g/
# ./config --prefix=/opt/openssl -DOPENSSL_LOAD_CONF --openssldir=/home/glaum/engine/deps/openssl-1.1.1g/apps
./config no-asm -g3 -O0 -fno-omit-frame-pointer -fno-inline-functions
make

# build curl
cd ..
wget https://curl.se/download/curl-7.78.0.zip
unzip curl-7.78.0.zip 
rm -rf unzip curl-7.78.0.zip
cd curl-7.78.0/
CPPFLAGS="-I/home/glaum/engine/deps/openssl-1.1.1g/include" LDFLAGS="-L/home/glaum/engine/deps/openssl-1.1.1g" ./configure --enable-debug --with-openssl -enable-libcurl-option HAVE_OPENSSL_ENGINE_H 
make

# build softhsm
cd ..
wget 