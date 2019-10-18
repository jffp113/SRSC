package SecureProtocol.Security;

public class Signer {

    private static Signer signer = new Signer();

    private Signer() {

    }

    public String doSign(String contentToSign){
        return null;
    }

    public static Signer getInstace(){
        return signer;
    }

}
