package SecureProtocol.SecureHandshake.Messages;

import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.cert.Certificate;

public class SAAHPResponse {

    private SAAHPHeader header;

    public SAAHPResponse(Certificate cert, SAAHPHeader header){
        this.header = header;
    }

    public void sendResponseToOutputStream(DataOutputStream out) {
        //TODO

    }

    public static SAAHPResponse getResponseFromInputStream(DataInputStream in)  {
        //TODO

    }
}
