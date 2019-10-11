package SMCP.Message;

import java.util.Base64;

public class Utils {

    public static String Base64Encode(byte[] input){
        return Base64.getEncoder().encode(input).toString();
    }
}
