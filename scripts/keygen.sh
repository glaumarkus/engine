# create key
openssl ecparam -name brainpoolP384r1 -genkey -out private_key.pem

# extract public key
openssl ec -in private_key.pem -pubout -out public_key.pem

# read parameters
openssl ec -in private_key.pem -noout -text -param_out

# make key for alice
openssl ecparam -name brainpoolP384r1 -genkey -out alice_pkey.pem

# make key for bob
openssl ecparam -name brainpoolP384r1 -genkey -out bob_pkey.pem

# create self signed certificate
openssl req -x509 -new -key private_key.pem -out certificate.pem -days 365