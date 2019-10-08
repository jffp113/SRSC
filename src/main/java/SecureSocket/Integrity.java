package SecureSocket;

import SecureSocket.KeyManagement.KeyManager;
import SecureSocket.misc.XMLSecurityProperty;

import java.security.MessageDigest;
import java.util.Properties;

public class Integrity {

    private MessageDigest hashF;
    private Properties prop;
    public Integrity(Properties prop){
        this.prop =prop;
        try{
            hashF = MessageDigest.getInstance(prop.getProperty(XMLSecurityProperty.INTHASH));
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public byte[] hash(byte[] input){
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
