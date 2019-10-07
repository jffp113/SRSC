package SecureSocket.KeyManagement;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.util.Properties;

public class KeyManager {

    private KeyStore keyStore;
    private Properties prop;

    public KeyManager(Properties prop) throws Exception{
        this.prop = prop;
       keyStore = KeyStore.getInstance(prop.getProperty("keystoreType"));
       FileInputStream stream = new FileInputStream(prop.getProperty("keystoreName"));
       keyStore.load(stream,prop.getProperty("keystorePassword").toCharArray());
       stream.close();
    }

    public Key getKey(String keyName) throws  Exception{
        return keyStore.getKey(keyName, prop.getProperty("keystorePassword").toCharArray());
    }

    public boolean genKeyStore(String specs){
        return false ;//TODO
    }
}
