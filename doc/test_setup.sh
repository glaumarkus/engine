# host server
openssl s_server -cert server-cert.pem -key server-key.pem -accept 443 -Verify 2

# connect with client
curl --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem https://localhost:443
