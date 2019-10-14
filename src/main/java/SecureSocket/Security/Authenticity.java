package SecureSocket.Security;

import SecureSocket.KeyManagement.KeyManager;
import SecureSocket.EndPoints.EndPoint;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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
            byte[] mac = new byte[message.length + hMac.getMacLength()];

            //mac = (message) + hmac
            System.arraycopy(message, 0, mac, 0, message.length);

            hMac.init(hMacKey);
            byte[] hmac = hMac.doFinal(message);

            //mac = message + (hmac)
            System.arraycopy(hmac, 0, mac, message.length, hmac.length);

            return mac;
        });
    }

    ////TODO: TIRAR ESTE METODO E VERIFICAR SÓ COM O GETHASH
    public byte[] verifyMac(byte[] mac) {
        return handleException(()->{

            int messageLength = mac.length - hMac.getMacLength();
            byte[] message = new byte [mac.length - hMac.getMacLength()];
            System.arraycopy(mac, 0, message, 0, messageLength);

            byte[] messageMac = new byte[hMac.getMacLength()];
            System.arraycopy(mac, messageLength, messageMac, 0, hMac.getMacLength());

            //Verificar mac
            hMac.init(hMacKey);
            byte[] h = hMac.doFinal(message);


            String a = new String(Base64.getEncoder().encode(h));
            String b = new String(Base64.getEncoder().encode(messageMac));

            if(a.equals(b)){
                //verificado
                return message;
            }else{
                throw new Exception();
            }
        });
    }

    public int getMacSize(){
        return hMac.getMacLength();
    }

}
