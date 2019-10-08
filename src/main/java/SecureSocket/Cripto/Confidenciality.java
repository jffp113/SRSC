package SecureSocket.Cripto;

import SecureSocket.Handler;
import SecureSocket.KeyManagement.KeyManager;
import SecureSocket.misc.EndPoint;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class Confidenciality {

    private Cipher c;
    private Key key;
    private IvParameterSpec ivSpec;
    private KeyManager keyRing;
    private EndPoint ep;

    public Confidenciality(String id, KeyManager keyManager) throws Exception {
        keyRing = keyManager;
        this.ep = keyManager.getEndPoint(id);
        c = Cipher.getInstance(ep.getSEA() + "/"
                + ep.getMODES() + "/"
                + ep.getPADDING());

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
