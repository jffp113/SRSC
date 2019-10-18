package SecureProtocol.Security.IV;

import java.security.spec.AlgorithmParameterSpec;

public class IVPair {
    private AlgorithmParameterSpec alg;
    private byte[] iv;

    public IVPair(AlgorithmParameterSpec alg, byte[] iv) {
        this.alg = alg;
        this.iv = iv;
    }

    public AlgorithmParameterSpec getAlg() {
        return alg;
    }

    public byte[] getMessage() {
        return iv;
    }
}
