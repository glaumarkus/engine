openssl s_server -Verify 2 -cert leaf_cert.crt -key leaf_key.pem -tls1_3 localhost:4433 -HTTP
openssl s_server -Verify 2 -cert server.pem -key server.key -tls1_3 localhost:4433 -HTTP


openssl s_client -CAfile root_ca.crt -cert leaf_cert.crt -key leaf_key.pem -no_ticket -debug -connect localhost:4433
openssl s_client -CAfile client.pem -cert server.pem -key server.key -no_ticket -debug -connect localhost:4433


curl --cacert root_ca.crt --cert leaf_cert.crt --key leaf_key.pem https://localhost:4433
curl --cacert client.pem --cert server.pem --key server.key https://localhost:4433