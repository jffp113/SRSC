package SecureSocket.Security.IV;

import javafx.util.Pair;

import java.security.spec.AlgorithmParameterSpec;

public class IVEmptyBuilder implements IVMessageBuilder {

    @Override
    public byte[] buildMessageWithIV(byte[] message) {
        return message;
    }

    @Override
    public IVPair unbuildMessageWithIV(byte[] message) {
        return new IVPair(null,message);
    }

    @Override
    public AlgorithmParameterSpec getSpec() {
        return null;
    }
}