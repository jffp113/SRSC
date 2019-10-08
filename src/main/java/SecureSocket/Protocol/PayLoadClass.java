package SecureSocket.Protocol;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

public class PayLoadClass {

    private String FromPeerID;
    private int SeqNr;
    private int RandomNonce;
    private byte[] Message_IntegrityControl;

    public PayLoadClass(byte[] payLoad) throws IOException {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(payLoad,0,payLoad.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        FromPeerID = dataStream.readUTF();
        SeqNr = dataStream.readInt();
        RandomNonce = dataStream.readInt();
        Message_IntegrityControl = dataStream.readAllBytes();
    }

    public String getFromPeerID() {
        return FromPeerID;
    }

    public int getSeqNr() {
        return SeqNr;
    }

    public int getRandomNonce() {
        return RandomNonce;
    }

    public byte[] getMessage_IntegrityControl() {
        return Message_IntegrityControl;
    }
}
