package SMCP.Message.Exceptions;

public class SMCPException extends RuntimeException {
    public SMCPException(String message) {
        super("["+message+"] Don't match.");
    }
}
