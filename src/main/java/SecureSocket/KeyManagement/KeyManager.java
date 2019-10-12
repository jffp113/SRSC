package SecureSocket.KeyManagement;

import SecureSocket.EndPoints.EndPoint;
import SecureSocket.EndPoints.XMLSecurityProperty;
import SecureSocket.Security.IV.IVEmptyBuilder;
import SecureSocket.Security.IV.IVGCMBuilder;
import SecureSocket.Security.IV.IVGeneralBuilder;
import SecureSocket.Security.IV.IVMessageBuilder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KeyManager {

    //TODO this passwords are temporary
    private static final String PASSWORD = "Teste";
    private static final String KEYSTORE_FILE = "keystore.JCEKS";
    private KeyStore keyStore;
    private Map<String,EndPoint> propertiesMap;

    public KeyManager() throws Exception{
        propertiesMap = new HashMap<>();
        genKeyStore(new XMLSecurityProperty("smcpendpoints.conf").getEndPoints());
    }

    public Key getKey(String keyName) throws  Exception{

        return keyStore.getKey(keyName,PASSWORD.toCharArray());
    }

    public EndPoint getEndPoint(String id){
        return propertiesMap.get(id);
    }

    public boolean genKeyStore(List<EndPoint> endPoints) throws Exception {
        File f = new File(KEYSTORE_FILE);
        boolean exists = f.exists();
        createKeyStore(f, PASSWORD);

            for(EndPoint ep : endPoints){
                //Generate Key for chat
                propertiesMap.put(ep.getIP_PORT(), ep);

                if(!exists) {
                    generateKeyAndStore(
                            ep.getIP_PORT(),
                            ep.getSEA(),
                            Integer.parseInt(ep.getSEAKS()));
                    generateKeyAndStore(ep.getIP_PORT()+"MAC",
                            ep.getMAC(),
                            Integer.parseInt(ep.getMAKKS()));


                }
            }

        return true ;
    }

    private KeyStore createKeyStore(File file, String pw) throws Exception {
        keyStore = KeyStore.getInstance("JCEKS");

        if (file.exists()) {
            keyStore.load(new FileInputStream(file), pw.toCharArray());
        } else {
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(file), pw.toCharArray());
        }

        return keyStore;
    }

    private void generateKeyAndStore(String name,String type) throws Exception {
        this.generateKeyAndStore(name,type,null);
    }

    private void generateKeyAndStore(String name, String type, Integer size) throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance(type);

        if(size != null)
            gen.init(size);

        SecretKey secretKey = gen.generateKey();

        store(name, secretKey);
    }


    public IVMessageBuilder getIV(Cipher cipher) throws Exception {
        String alg = cipher.getAlgorithm();
        IVMessageBuilder parameterSpec;

        if(alg.contains("GCM")){
            parameterSpec = new IVGCMBuilder(new GCMParameterSpec(128,generateIV(cipher))); //TODO whats TLen
        }
        else if(alg.contains("ECB")){
            return new IVEmptyBuilder();
        }
        else{
            parameterSpec = new IVGeneralBuilder(new IvParameterSpec(generateIV(cipher)));
        }

        return parameterSpec;
    }

    private byte[] generateIV(Cipher cipher){
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);

        //store("IV".concat(cipher.getAlgorithm()),new SecretKeySpec(iv, cipher.getAlgorithm()));
        return iv;

    }

    private void store(String name,SecretKey key) throws Exception{
        KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(PASSWORD.toCharArray());
        keyStore.setEntry(name, keyStoreEntry, keyPassword);
        keyStore.store(new FileOutputStream(KEYSTORE_FILE), PASSWORD.toCharArray());
    }



}
