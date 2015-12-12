The JKS contains:
- the root certificate of the CA
- the keypair of the verifier service
- the certificate of the verifier service, signed by the CA

eid.p12 is the keypair+certificate of the user, including the CA certificate chain

All passwords are "123456"

How to create:
- create a CA http://datacenteroverlords.com/2012/03/01/creating-your-own-ssl-certificate-authority/
- create a server keypair (with keytool or Portecle) in a JKS
- generate a CSR based on that keypair
- sign the CSR using openssl: `openssl  x509  -req  -CA CA/rootCA.pem -CAkey CA/rootCA.key -in c:/tmp/eid.csr -out c:/tmp/eid.cer -days 3650  -CAcreateserial`
- import the root CA into the JKS
- import the CA reply (the cer resulting from the CSR signing) into the JKS
- repeat the steps for a client JKS and convert it to p12
