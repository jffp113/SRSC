package SecureProtocol.SecureHandshake.Messages.Components;

public enum SAAHPCode {

    ACCEPTED(200,"Accepted"),
    NOT_MODIFIED(201,"Not Modified"),
    REJECTED(100,"Rejected"),
    CRIPTOGRAPHY_NOT_ACCEPTED(101,"Cryptography Not Accepted"),
    INTERNAL_ERROR(101,"Internal Error"),
    VERSION_NOT_SUPPORTED(103,"Version Not Supported");

    private final int code;
    private final String representation;

    SAAHPCode(int code, String representation) {
        this.code = code;
        this.representation = representation;
    }

    @Override
    public String toString() {
        return String.format("%d %s",code,representation);
    }

}
