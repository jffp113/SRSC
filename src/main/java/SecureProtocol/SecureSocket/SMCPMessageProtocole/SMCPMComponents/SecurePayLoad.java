package SecureProtocol.SecureSocket.SMCPMessageProtocole.SMCPMComponents;

import SecureProtocol.Security.Security;
import java.io.*;

import static SecureProtocol.Utils.base64Encode;

public class SecurePayLoad {

    public static byte[] generateSecurePayLoad(byte[] message, String peerID, int seqnum, Security sec) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeUTF(peerID);
        dataStream.writeInt(seqnum);
        dataStream.writeLong(System.nanoTime());
        dataStream.writeUTF(base64Encode(message));
        dataStream.writeUTF(base64Encode(sec.getIntegrity().getHash(message)));

        return sec.getSymmetricEncription().encrypt(byteStream.toByteArray());
    }

}
