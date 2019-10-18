package SecureProtocol.SecureHandshake.Messages;

import java.io.DataInputStream;

public class SAAHPResponse {

    private final DataInputStream out;

    public SAAHPResponse(DataInputStream out) {
        this.out = out;
    }
}
