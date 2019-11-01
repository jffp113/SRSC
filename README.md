# SRSC - TP1

#Ir para a pasta "Package" onde se encontram os JARs
	cd Package

#INFOS
	#Developers:
		#Keys e keystore necessárias para assinar os jars + jars não assinados.
	#PEER - [Client]:
		#CA: Cópia da CA para ser usada.
		#certchain.crt: cadeia de certificados (ROOT <- Cliente).
		#certificados do client e a sua keystore.
		#SecureMChatClient[Signed]: jar assinado.
	#PEER - [Server]:
		#CA: Cópia da CA para ser usada.
		#certchain.crt: cadeia de certificados (ROOT <- Server).
		#certificados do servidor e a sua keystore.
		#SAAHPServer[Signed]: jar assinado.

#NOTA:INFO
	#META-INF: Diretoria automática do IntelliJ para gerar JARS automáticamente.


#SETUP
	#Entrar em "CA" (Fazer em cada peer)
		cd CA
	#Criar par de chaves da CA (PrivateKey + CertificateNoSign)
		keytool -genkeypair -alias ca -keystore test.jks -dname "CN=Root CA" -storepass password -keypass password -ext bc=ca:true
	#Criar certificado autoassinado da CA (CertificateSign)
		keytool -export -alias ca -keystore test.jks -storepass password -file caroot.crt
	#importar o certificado autoassinado para uma keystore
		keytool -import -alias ca -file caroot.crt -keystore catrustedcert.jks -storepass chageit -keypass changeit

	#Entrar em "[PEER]-Client"
		cd ../"PEER - [Client]"
	#Criar par de chaves do Client (PrivateKey + CertificateNoSign)
		keytool -genkeypair -alias leaf -keystore leaf.jks -keyalg RSA -keysize 2048 -dname "CN=Leaf" -storepass password -keypass password
	#Gerar certificado não assinado do cliente
		keytool -certreq -keystore leaf.jks -storepass password -alias leaf -file leaf.csr
	#Gerar certificado assinado pela CA
		keytool -gencert -keystore ../"PEER - [CA]"/KeyStore_CA.jks -storepass password -alias PrivateKey_CA -infile leaf.csr -outfile leaf.crt
	#Criar cadeia de certificados (CA <- Client)
		cat ../"PEER - [CA]"/Certificate_CA.crt > certchain.crt
		cat leaf.crt >> certchain.crt

	#Entrar em "[PEER]-Server"
		cd ../"PEER - [Server]"
	#Criar par de chaves do Servidor (PrivateKey + CertificateNoSign)
		keytool -genkeypair -alias leaf -keystore leaf.jks -keyalg RSA -keysize 2048 -dname "CN=Leaf" -storepass password -keypass password
	#Gerar certificado não assinado do servidor
		keytool -certreq -keystore leaf.jks -storepass password -alias leaf -file leaf.csr
	#Gerar certificado assinado pela CA
		keytool -gencert -keystore ../"PEER - [CA]"/KeyStore_CA.jks -storepass password -alias PrivateKey_CA -infile leaf.csr -outfile leaf.crt
	#Criar cadeia de certificados (CA <- Servidor)
		cat ../"PEER - [CA]"/Certificate_CA.crt > certchain.crt
		cat leaf.crt >> certchain.crt

	#Developers (Gerar as chaves e a keystore para assinar os jars): password:password
		keytool -genkey -alias myKey -keyalg RSA -keystore keys.jks -keysize 2048
		keytool -export -alias myKey -keystore keys.jks -file publickey.cer

	#Assinar .jars
		jarsigner -keystore keys.jks -storepass password -keypass password --signedjar SecureMChatClient[Signed].jar SecureMChatClient.jar myKey
		jarsigner -keystore keys.jks -storepass password -keypass password --signedjar SAAHPServer[Signed].jar SAAHPServer.jar myKey


	#Correr Servidor para testar
		java -jar SAAHPServer.jar

	#Correr Clientes para testar 
		java -jar SecureMChatClient hj hjhjhj 224.5.6.7 9000
		java -jar SecureMChatClient jorge jorge123 224.5.6.7 9000


