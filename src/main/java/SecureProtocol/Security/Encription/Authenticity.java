package SecureProtocol.Security.Encription;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class Authenticity extends AbstractSecurity {

    private Mac hMac;
    private Key hMacKey;

    public Authenticity(String mac, Key key) {
        try {
            hMac = Mac.getInstance(mac);
            hMacKey = new SecretKeySpec(key.getEncoded(), mac);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public byte[] generateMac(byte[] message) {
        return handleException(()->{
            hMac.init(hMacKey);
            byte[] mac = hMac.doFinal(message);
            return mac;
        });
    }

    public int getMacSize(){
        return hMac.getMacLength();
    }

}
