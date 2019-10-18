package SecureProtocol.Security.IV;

import javax.crypto.spec.IvParameterSpec;
import java.io.*;

public class IVGeneralBuilder extends IvParameterSpec implements IVMessageBuilder {

    private IvParameterSpec spec;

    public IVGeneralBuilder(IvParameterSpec spec) {
        super(spec.getIV());
        this.spec = spec;
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
            dataStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new IVPair(new IvParameterSpec(iv),messageE);
    }


    @Override
    public IvParameterSpec getSpec() {
        return spec;
    }
}
