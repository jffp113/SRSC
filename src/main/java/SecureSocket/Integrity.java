package SecureSocket;

import java.security.MessageDigest;
import java.util.Properties;

public class Integrity {

    private MessageDigest hashF;

    public Integrity(Properties properties){
        try{
            hashF = MessageDigest.getInstance(getAlg());
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public byte[] Hash(byte[] input){
        return hashF.digest(input);
    }

    public boolean compareTextWithHash(byte[] input, byte[] hash){
        return hashF.digest(input).equals(hash);
    }

    //TODO
    private String getAlg(){
        return null;
    }

}
