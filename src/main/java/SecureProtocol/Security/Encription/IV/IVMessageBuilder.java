package SecureProtocol.Security.Encription.IV;

import java.security.spec.AlgorithmParameterSpec;

public interface IVMessageBuilder extends AlgorithmParameterSpec {

    byte[] buildMessageWithIV(byte[] message);

    IVPair unbuildMessageWithIV(byte[] message);

    AlgorithmParameterSpec getSpec();
}
