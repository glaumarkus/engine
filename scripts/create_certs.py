import trustme

ca = trustme.CA()
cert = ca.issue_cert("test-backend.com")

# Write the certificate and private key the server should use
server_key = "server.key"
server_cert = "server.pem"
cert.private_key_pem.write_to_path(path=server_key)
with open(server_cert, mode="w") as f:
    f.truncate()
for blob in cert.cert_chain_pems:
    blob.write_to_path(path=server_cert, append=True)

# Write the certificate and private key the client should use
client_cert = "client.pem"
ca.cert_pem.write_to_path(path=client_cert)
