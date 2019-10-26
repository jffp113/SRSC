package SecureProtocol.SecureSocket.KeyManagement;

import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.SecureSocket.EndPoints.XMLSecurityProperty;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.util.Collection;
import java.util.Map;

public class KeyManager {

    //TODO this passwords are temporary
    private static final String PASSWORD = "Teste";
    private static final String KEYSTORE_FILE = "keystore.JCEKS";
    private KeyStore keyStore;
    private Map<String,EndPoint> endPointsMap;

    private static KeyManager keyManager;

    public static KeyManager getInstance() throws Exception {
        if(keyManager == null) {
            keyManager = new KeyManager();
            keyManager.genKeyStore(XMLSecurityProperty.getEndPoints("SMCP.conf").values());
        }

        return keyManager;
    }

    private KeyManager() throws Exception{
        endPointsMap = XMLSecurityProperty.getEndPoints("SMCP.conf");
        genKeyStore(endPointsMap.values());
    }

    public void genKeyStore(Collection<EndPoint> endPoints) throws Exception {
        File f = new File(KEYSTORE_FILE);
        boolean exists = f.exists();

        createKeyStore(f, PASSWORD);

        if(!exists) {
            for(EndPoint ep : endPoints){
                //Generate Key for chat
                generateKeyAndStore(
                        ep.getMulticastGroup(),
                        ep.getSea(),
                        ep.getSeaks());

                generateKeyAndStore(
                        "MAC/"+ ep.getMulticastGroup(),
                        ep.getMac(),
                        ep.getMakks());
            }
        }
    }

    private KeyStore createKeyStore(File file, String pw) throws Exception {
        keyStore = KeyStore.getInstance("JCEKS");
        if (file.exists())
            keyStore.load(new FileInputStream(file), pw.toCharArray());
        else {
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(file), pw.toCharArray());
        }
        return keyStore;
    }

    private void generateKeyAndStore(String alias, String type, Integer size) throws Exception {
        store(alias, KeyManager.genRandomKey(type, size));
    }

    private void store(String name,SecretKey key) throws Exception{
        KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(PASSWORD.toCharArray());
        keyStore.setEntry(name, keyStoreEntry, keyPassword);
        keyStore.store(new FileOutputStream(KEYSTORE_FILE), PASSWORD.toCharArray());
    }

    public Key getKey(String keyName) throws  Exception{
        return keyStore.getKey(keyName, PASSWORD.toCharArray());
    }

    public EndPoint getEndPoint(String multicastGroup){
        return endPointsMap.get(multicastGroup);
    }

    public static SecretKey genRandomKey(String type, Integer size) throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance(type);
        if(size != null)
            gen.init(size);
        SecretKey secretKey = gen.generateKey();
        return  secretKey;
    }

}
