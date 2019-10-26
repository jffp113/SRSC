keytool -genkey -alias myKey -keyalg RSA -keystore keys.jks -keysize 2048
keytool -export -alias myKey -keystore keys.jks -file publickey.cer
