package SMCP.CIA;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public class Confidentiality {

    private Cipher c;
    private Key key;
    private AlgorithmParameterSpec ivSpec;

    public Confidentiality(String sea, int seaks, String mode, String padding, Key key) {
        //TODO: seaks usado onde???
        try {
            c = Cipher.getInstance(sea + "/" + mode + "/" + padding);
            this.key = key;
            this.ivSpec = null; //TODO: criar aqui o IV (secalhar não é preciso guardar o IV?)
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] dec) {
        try {
            c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            return c.doFinal(dec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] decrypt(byte[] enc) {
        try {
            c.init(Cipher.DECRYPT_MODE, key, ivSpec);
            return c.doFinal(enc);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }
}
