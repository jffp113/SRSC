cp ./target/SAAHP-client.jar ./Package/SAAHP-client.jar
cp ./target/SAAHP-server.jar ./Package/SAAHP-server.jar
jarsigner -keystore SignerKeystore/keys.jks -storepass changeit -keypass changeit --signedjar ./Package/SAAHP-client-signed.jar ./target/SAAHP-client.jar myKey
jarsigner -keystore SignerKeystore/keys.jks -storepass changeit -keypass changeit --signedjar ./Package/SAAHP-server-signed.jar ./target/SAAHP-server.jar myKey

#jarsigner -verify ./Package/SAAHP-client-signed.jar
#jarsigner -verify ./Package/SAAHP-server-signed.jar
