#!/usr/bin/env bash

#
echo "------------------------------------------------------------------------"
echo "Establishment of the CA Root and CA Root Level Certificate"
echo "------------------------------------------------------------------------"
# 1) To begin, we first generate a key pair which will be used as the CA,
#    the private key will be used to sign the certificate it issues.

keytool -genkeypair -alias ca -keystore test.jks -dname "CN=Root CA" -storepass password -keypass password -ext bc=ca:true

keytool -export -alias ca -keystore test.jks -storepass password -file caroot.crt

echo "CA generated a public-private pair, stored in keystore test.jks"
echo "and a CA root certificate is stored in caroot.crt"
echo "Root CA ESTABLISHED"
echo ""
echo "---------------------------------------------------------"
echo The Root CA Certificate
echo "---------------------------------------------------------"
keytool -printcert -file caroot.crt
echo "---------------------------------------------------------"

echo "------------------------------------------------------------------------"
echo "Now, can import the CA root as a trusted certificate"
echo "Let's store it in a catrustedcert keystore"
echo "------------------------------------------------------------------------"
keytool -import -alias ca -file caroot.crt -keystore catrustedcert.jks -storepass chageit -keypass changeit


echo "------------------------------------------------------------------------"
echo "Second Level Certificate"
echo "------------------------------------------------------------------------"
# 2) Then, generate a key pair where the certificate of it will be signed
#    by the CA above (itself).
#    So this an selfigned / selfissued  certificate


keytool -genkeypair -alias leaf -keystore leaf.jks -keyalg RSA -keysize 2048 -dname "CN=Leaf" -storepass password -keypass password

#  3) Next, a certificate request for the "CN=Leaf" certificate needs to be
#  created.

keytool -certreq -keystore leaf.jks -storepass password -alias leaf -file leaf.csr

#  4) Now creating the certificate with the certificate request generated
#  above.

keytool -gencert -keystore test.jks -storepass password -alias ca -infile leaf.csr -outfile leaf.crt

#  5) An output certificate file leaf.crt will be created. Now let's see
#  what its content is.

echo
echo "---------------------------------------------------------"
echo The 2nd LEVEL Certificate
echo "---------------------------------------------------------"
keytool -printcert -file leaf.crt
echo "---------------------------------------------------------"

echo
echo "------------------------------------------------------------------------"
echo "Create the Certificate Chain CA-Root:Leaf"
echo "------------------------------------------------------------------------"

cat caroot.crt > certchain.crt
cat leaf.crt >> certchain.crt

keytool -printcert -file certchain.crt

keytool -import -file certchain.crt -keystore certchainkeystore.jks -alias chain1 -storepass changeit -keypass changeit
