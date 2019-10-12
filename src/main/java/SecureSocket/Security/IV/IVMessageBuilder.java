package SecureSocket.Security.IV;

import javafx.util.Pair;

import java.security.spec.AlgorithmParameterSpec;

public interface IVMessageBuilder extends AlgorithmParameterSpec {

    byte[] buildMessageWithIV(byte[] message);

    IVPair unbuildMessageWithIV(byte[] message);

    AlgorithmParameterSpec getSpec();
}
