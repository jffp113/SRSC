package SMCP.CIA;

import SMCP.CIA.Exceptions.IntegrityException;
import SMCP.Message.Utils;

import java.security.MessageDigest;

public class Integrity {

    private MessageDigest hashFun;

    public Integrity(String inthash) {
        try{
            hashFun = MessageDigest.getInstance(inthash);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public byte[] generateHash(byte[] input){
        return hashFun.digest(input);
    }

    public int getHashLength(){
        return hashFun.getDigestLength();
    }

    public void verifyInput_Hash(byte[] input, byte[] hash){
        String inputHash_b64 = Utils.Base64Encode(generateHash(input));
        String hash_b64 = Utils.Base64Encode(hash);
        if(!inputHash_b64.equals(hash_b64))
            throw new IntegrityException();
    }
}
