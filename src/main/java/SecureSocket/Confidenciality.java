package SecureSocket;

import SecureSocket.KeyManagement.KeyManager;
import SecureSocket.misc.XMLSecurityProperty;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Properties;

public class Confidenciality {

    private Cipher c;
    private Key key;
    private IvParameterSpec ivSpec;
    private KeyManager keyRing;
    private Properties prop;

    public Confidenciality(String id, KeyManager keyManager) throws Exception {
        keyRing = keyManager;
        this.prop = keyManager.getPropertiesFor(id);
        c = Cipher.getInstance(prop.getProperty(XMLSecurityProperty.SEA) + "/"
                + prop.get(XMLSecurityProperty.MODE) + "/"
                + prop.getProperty(XMLSecurityProperty.PADDING));

        key = keyRing.getKey(id);
        ivSpec = keyRing.getIV(c);
    }

    public byte[] handleException(Handler handler){
        try {
            return handler.handle();
        } catch ( Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] encrypt(byte[] input){
        return handleException(()->{
            c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            return c.doFinal(input);
        });
    }

    public byte[] decrypt(byte [] input){
        return handleException(()->{
            c.init(Cipher.DECRYPT_MODE, key, ivSpec);
            return c.doFinal(input);
        });
    }

}
