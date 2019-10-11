package SecureSocket;

import java.util.Base64;

public class Utils {

    public static String base64Encode(byte[] input) {
       return Base64.getEncoder().encodeToString(input);
    }
}
