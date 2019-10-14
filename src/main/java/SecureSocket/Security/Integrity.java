package SecureSocket.Security;

import java.security.MessageDigest;

public class Integrity extends AbstractSecurity{

    private MessageDigest hashF;

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

    public int getHashSize(){
        return hashF.getDigestLength();
    }

}
