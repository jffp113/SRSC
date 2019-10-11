package SecureSocket.Security;

import SecureSocket.Exception.SMSCException;
import SecureSocket.KeyManagement.KeyManager;

import java.security.MessageDigest;

public class Integrity extends AbstractSecurity{

    private static final String NO_INTEGRITY = "Don't have integrity.";

    private MessageDigest hashF;

    private static Integrity sigleton;

    public Integrity(String intHash){
        try{
            hashF = MessageDigest.getInstance(intHash);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public byte[] getHash(byte[] input){
        return hashF.digest(input);
    }

    public void compareHash(byte[] input, byte[] hash){
        if(!hashF.digest(input).equals(hash)){
            throw new SMSCException(NO_INTEGRITY);
        }
    }

    public static synchronized Integrity getInstance(String intHash) throws Exception {
        if(sigleton == null)
            sigleton = new Integrity(intHash);

        return sigleton;
    }

}
