package SecureSocket.Cripto;

import SecureSocket.Exception.SMSCException;

import java.security.MessageDigest;

public class Integrity {

    private static final String NO_INTEGRITY = "Don't have integrity.";

    private MessageDigest hashF;

    public Integrity(String intHash){
        try{
            hashF = MessageDigest.getInstance(intHash);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public byte[] makeHash(byte[] input){
        return hashF.digest(input);
    }

    public int hashLength(){
        return hashF.getDigestLength();
    }

    /**
     * Compare HASH(input) with hash
     * @param input
     * @param hash
     */
    public void compare_InputHash_hash(byte[] input, byte[] hash){
        if(!hashF.digest(input).equals(hash)){
            throw new SMSCException(NO_INTEGRITY);
        }
    }

    public static <E> void checkEquality(E x1, E x2) {
        if(!x1.equals(x2)){
            throw new SMSCException(NO_INTEGRITY);
        }
    }

}
