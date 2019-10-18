package SecureProtocol.Security;

import SecureProtocol.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AssymetricEncription {

    private Cipher cipher;

    public AssymetricEncription(){
        try {
            cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encript(String content, PublicKey key) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Utils.base64Encode(cipher.doFinal(content.getBytes()));

    }

    public String decript(String b64Content, PublicKey key) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Utils.base64Decode(b64Content)));
    }
}
