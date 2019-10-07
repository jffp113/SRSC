package SecureSocket;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Properties;

public class Confidenciality {

    private Cipher c;
    private Key key;
    private IvParameterSpec ivSpec;

    public Confidenciality(Properties properties) throws NoSuchProviderException, NoSuchPaddingException {
        //GUARDAR NOUTRO SITIO : MELHORIAS FUTURAS
        key = new SecretKeySpec(getKey(), getAlg());
        ivSpec = new IvParameterSpec(getIV());
        try {
            c = Cipher.getInstance(getCONF(), getAlg());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
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

    //TODO
    private byte[] getIV(){
        return null;
    }

    //TODO
    private byte[] getKey(){
        return null;
    }

    //TODO
    private String getAlg(){
        return null;
    }

    //TODO
    private String getCONF(){
        return null;
    }

}
