package SecureProtocol.Security;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.KeySpec;

public class Rekeying {

    public static Key xorKeyWithHash(String hash, Key key) throws Exception{
        byte[] newKeyBytes = xorWithKey(hash.getBytes(),key.getEncoded());
        return new SecretKeySpec(newKeyBytes,key.getAlgorithm());
    }

    private static byte[] xorWithKey(byte[] a, byte[] key) {
        byte[] out = new byte[key.length];
        for (int i = 0; i < key.length; i++) {
            out[i] = (byte) (key[i] ^ a[i%a.length]);
        }
        return out;
    }
}
