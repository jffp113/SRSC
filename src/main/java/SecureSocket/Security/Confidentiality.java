package SecureSocket.Security;

import SecureSocket.KeyManagement.KeyManager;
import SecureSocket.EndPoints.EndPoint;
import SecureSocket.Security.IV.IVMessageBuilder;
import SecureSocket.Security.IV.IVPair;
import javafx.util.Pair;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class Confidentiality extends AbstractSecurity{

    private static Confidentiality sigleton;

    private Cipher c;
    private Key key;
    private IVMessageBuilder ivSpec;
    private KeyManager keyRing;
    private EndPoint ep;
    private boolean isEncript;

    public Confidentiality(String id, KeyManager keyManager) throws Exception {
        keyRing = keyManager;
        this.ep = keyManager.getEndPoint(id);
        c = Cipher.getInstance(ep.getSEA() + "/"
                + ep.getMODES() + "/"
                + ep.getPADDING());

        key = keyRing.getKey(id);
    }


    public byte[] encrypt(byte[] input){
        return handleException(()->{
            ivSpec = keyRing.getIV(c);
            c.init(Cipher.ENCRYPT_MODE, key, ivSpec.getSpec());
            isEncript = true;

            return ivSpec.buildMessageWithIV(c.doFinal(input));
        });
    }

    public byte[] decrypt(byte [] input){
        return handleException(()->{
            IVPair messageAndIV = ivSpec.unbuildMessageWithIV(input);
            c.init(Cipher.DECRYPT_MODE, key, messageAndIV.getAlg());
            isEncript = false;

            return c.doFinal(messageAndIV.getMessage());
        });
    }

    public static synchronized Confidentiality getInstance(String id, KeyManager keyManager) throws Exception {
        if(sigleton == null)
            sigleton = new Confidentiality(id,keyManager);

        return sigleton;
    }

}
