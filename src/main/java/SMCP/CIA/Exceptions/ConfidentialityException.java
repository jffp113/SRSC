package SMCP.CIA.Exceptions;

public class ConfidentialityException extends RuntimeException {
    public ConfidentialityException() {
        super("[Confidentiality] Cipher don't match.");
    }
}
