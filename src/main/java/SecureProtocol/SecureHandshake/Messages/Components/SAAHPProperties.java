package SecureProtocol.SecureHandshake.Messages.Components;

public enum SAAHPProperties {
    CONTENT_LENGTH("Content-Length");

    private final String value;

    SAAHPProperties(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
