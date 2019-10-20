package SecureProtocol.Security.Encription;

import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.Utils;

import java.security.*;

public class Signer {

    private static Signer signer = new Signer();

    private static final String SIGN_ALGORITHM = "SHA512withRSA";

    private Signature signature;

    private Signer() {
        try {
            signature = Signature.getInstance(SIGN_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String doSign(String contentToSign) throws SignatureException, InvalidKeyException {
        signature.initSign(CertificateUtil.getPersonalPrivateKey());
        signature.update(contentToSign.getBytes());
        return Utils.base64Encode(signature.sign());
    }

    public boolean verifySignature(String message, String b64Sign,  PublicKey key) throws InvalidKeyException, SignatureException {
        signature.initVerify(key);
        signature.update(message.getBytes());
        return signature.verify(Utils.base64Decode(b64Sign));
    }

    public static Signer getInstace(){
        return signer;
    }

}
