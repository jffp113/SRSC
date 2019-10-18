package SecureProtocol.Security;

import SecureProtocol.Security.IV.*;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class SymmetricEncription extends AbstractSecurity{

    private Cipher c;
    private Key key;
    private IVMessageBuilder ivSpec;

    private String mode;

    public SymmetricEncription(String sea, String mode, String padding, Key key) throws Exception {
        this.mode = mode;
        c = Cipher.getInstance(sea + "/" + mode + "/" + padding);
        this.key = key;
    }

    public byte[] encrypt(byte[] input){
        return handleException(()->{
            ivSpec = getIV(mode, c.getBlockSize());
            c.init(Cipher.ENCRYPT_MODE, key, ivSpec.getSpec());

            return ivSpec.buildMessageWithIV(c.doFinal(input));
        });
    }

    public byte[] decrypt(byte [] input){
        return handleException(()->{
            IVPair messageAndIV = ivSpec.unbuildMessageWithIV(input);
            c.init(Cipher.DECRYPT_MODE, key, messageAndIV.getAlg());
            return c.doFinal(messageAndIV.getMessage());
        });
    }

    public IVMessageBuilder getIV(String mode, int blockSize) {
        IVMessageBuilder parameterSpec;

        if(mode.equalsIgnoreCase("GCM"))
            parameterSpec = new IVGCMBuilder(new GCMParameterSpec(128,generateIV(blockSize)));
        else if(mode.equalsIgnoreCase("ECB"))
            return new IVEmptyBuilder();
        else
            parameterSpec = new IVGeneralBuilder(new IvParameterSpec(generateIV(blockSize)));
        return parameterSpec;
    }

    private byte[] generateIV(int blockSize){
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[blockSize];
        randomSecureRandom.nextBytes(iv);
        return iv;
    }


}
