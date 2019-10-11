package SMCP.CIA.Exceptions;

public class AuthenticityException extends RuntimeException {
    public AuthenticityException() {
        super("[Authenticity] MAC violated.");
    }
}
