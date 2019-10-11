package SMCP.CIA;

import SMCP.CIA.Exceptions.AuthenticityException;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Authenticity {

    private Key key;
    private Mac hMac;
    private Key hMacKey;

    public Authenticity(String mac, int makks, Key key) {
        //TODO: MAKKS é usado onde?
        this.key = key;
        try {
            hMac = Mac.getInstance(mac);
            hMacKey = new SecretKeySpec(key.getEncoded(), mac);
            hMac.init(hMacKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public byte[] generateMac(byte[] smcpMessage) {
        return hMac.doFinal(smcpMessage);
    }

    public void verifyMac(byte[] smcpMessage, byte[] mac) {
        String smcpMessage_b64 = Base64.getEncoder().encode(hMac.doFinal(smcpMessage)).toString();
        String mac_b64 = Base64.getEncoder().encode(mac).toString();

        if(!smcpMessage_b64.equals(mac_b64))
            throw new AuthenticityException();
    }

    public int getMacSize() {
        return hMac.getMacLength();
    }
}
