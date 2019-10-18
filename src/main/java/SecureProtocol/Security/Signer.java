package SecureProtocol.Security;

import java.security.PublicKey;

public class Signer {

    private static Signer signer = new Signer();

    private Signer() {

    }

    public String doSign(String contentToSign){
        return null;
    }

    public boolean verifySignature(PublicKey key){
        return false;
    }

    public static Signer getInstace(){
        return signer;
    }

}
