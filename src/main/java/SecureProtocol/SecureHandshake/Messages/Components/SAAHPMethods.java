package SecureProtocol.SecureHandshake.Messages.Components;

public enum SAAHPMethods {
    JOINCHAT("JOINCHAT");

    private final String value;


    SAAHPMethods(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
