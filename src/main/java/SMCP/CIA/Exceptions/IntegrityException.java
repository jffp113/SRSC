package SMCP.CIA.Exceptions;

public class IntegrityException extends RuntimeException {
    public IntegrityException() {
        super("[Integrity] Hash don't match.");
    }
}
