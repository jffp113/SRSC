package SecureSocket.KeyManagement;

import SecureSocket.EndPoints.EndPoint;
import SecureSocket.EndPoints.XMLSecurityProperty;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
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
        genKeyStore(new XMLSecurityProperty("smcpendpoints.conf").getEndPoints()); //TODO Extract file name
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

    public AlgorithmParameterSpec getIV(Cipher cipher) throws Exception {
        Key iv = getKey("IV".concat(cipher.getAlgorithm()));
        String alg = cipher.getAlgorithm();
        AlgorithmParameterSpec parameterSpec;

        if(alg.contains("GCM")){
            if(iv == null){
                byte[] ivBytes = generateIVAndStore(cipher);
                parameterSpec = new GCMParameterSpec(128,ivBytes); //TODO whats TLen
            }else{
                parameterSpec = new GCMParameterSpec(128,iv.getEncoded());
            }
        }
        else if(alg.contains("ECB")){
            return null;
        }
        else{
            //General Case
            if(iv == null)
                parameterSpec = new IvParameterSpec(generateIVAndStore(cipher));
            else
                parameterSpec = new IvParameterSpec(iv.getEncoded());
        }

        return parameterSpec;
    }

    private byte[] generateIVAndStore(Cipher cipher) throws Exception{
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);

        store("IV".concat(cipher.getAlgorithm()),new SecretKeySpec(iv, cipher.getAlgorithm()));
        return iv;

    }

    private void store(String name,SecretKey key) throws Exception{
        KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(PASSWORD.toCharArray());
        keyStore.setEntry(name, keyStoreEntry, keyPassword);
        keyStore.store(new FileOutputStream(KEYSTORE_FILE), PASSWORD.toCharArray());
    }



}
