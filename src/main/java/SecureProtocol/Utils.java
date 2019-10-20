package SecureProtocol;

import SecureProtocol.SecureSocket.SMCPMessageProtocole.Exception.SMCPException;

import java.util.Base64;

public class Utils {

    private static final String RED = "\033[0;31m";     // RED
    public static final String RESET = "\033[0m";       // Text Reset

    public static String base64Encode(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    public static byte[] base64Decode(String input) {
        return Base64.getDecoder().decode(input);
    }

    public static <E> void verify(E actual , E expected, String message){ if(!actual.equals(expected)) throw new SMCPException(message); }

    public static void log(String message){
        System.out.println(RED + message + RESET);
    }

}

