package SecureSocket.Security.IV;

import javax.crypto.spec.GCMParameterSpec;
import java.io.*;

public class IVGCMBuilder extends GCMParameterSpec implements IVMessageBuilder {

   private GCMParameterSpec spec;

    public IVGCMBuilder(GCMParameterSpec spec) {
        super(spec.getTLen(),spec.getIV());
        this.spec = (GCMParameterSpec)spec;
    }

    @Override
    public byte[] buildMessageWithIV(byte[] message) {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);
        try {
            dataStream.write(spec.getIV());
            dataStream.writeInt(message.length);
            dataStream.write(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return byteStream.toByteArray();
    }

    public IVPair unbuildMessageWithIV(byte[] message) {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(message,0,message.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        byte[] iv = new byte[spec.getIV().length];
        byte[] messageE = null;
        try {
            dataStream.read(iv);
            messageE = new byte[dataStream.readInt()];
            dataStream.read(messageE);
        } catch (IOException e) {
            e.printStackTrace();
        }


        return new IVPair(new GCMParameterSpec(spec.getTLen(),iv),messageE);
    }


    @Override
    public GCMParameterSpec getSpec() {
        return spec;
    }
}
