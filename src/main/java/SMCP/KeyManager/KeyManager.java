package SMCP.KeyManager;

import SMCP.XML.EndPoint;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class KeyManager {

    //TODO this passwords are temporary
    private static final String PASSWORD = "Teste";
    private static final String KEYSTORE_FILE = "keystore.JCEKS";
    private KeyStore keyStore;

    public KeyManager(EndPoint endPoint) throws Exception{
        keyStore = KeyStore.getInstance("JCEKS");
        genKeyStore();
        if(!existKey(endPoint.getIp_port())) {
            SecretKey key = generateKey(endPoint.getSea(), endPoint.getSeaks());
            storeKey(endPoint.getIp_port(), key);
        }
    }

    public void genKeyStore() throws Exception {
        File file = new File(KEYSTORE_FILE);

        if (file.exists()) {
            keyStore.load(new FileInputStream(file), PASSWORD.toCharArray());
        } else {
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(file), PASSWORD.toCharArray());
        }
    }

    private boolean existKey(String name) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return keyStore.getKey(name, PASSWORD.toCharArray()) != null;
    }

    private SecretKey generateKey(String type, Integer size) throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance(type);
        if(size != null)
            gen.init(size);
        return gen.generateKey();
    }

    private void storeKey(String name, SecretKey key) throws Exception{
        KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(PASSWORD.toCharArray());
        keyStore.setEntry(name, keyStoreEntry, keyPassword);
        keyStore.store(new FileOutputStream(KEYSTORE_FILE), PASSWORD.toCharArray());
    }

    public Key getKey(String keyName) throws Exception {
        return keyStore.getKey(keyName, PASSWORD.toCharArray());
    }

    //------------------------------------------------------------------------------------------------

    //TODO: Daqui para baixo não vi, só usei. Preciso que me expliques! :)
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

        storeKey("IV".concat(cipher.getAlgorithm()),new SecretKeySpec(iv, cipher.getAlgorithm()));
        return iv;
    }
}
