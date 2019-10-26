package SecureProtocol.Security;

import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.SecureSocket.KeyManagement.KeyManager;
import SecureProtocol.Security.Encription.Authenticity;
import SecureProtocol.Security.Encription.Integrity;
import SecureProtocol.Security.Encription.Signer;
import SecureProtocol.Security.Encription.SymmetricEncription;

import java.security.Key;

public class Security {

    private KeyManager keyManager;

    private final SymmetricEncription symmetricEncription;
    private final Integrity integrity;
    private final Authenticity authenticity;

    private final EndPoint endPoint;

    //Phase1
    public Security(String multicastGroup) throws Exception{
        this.keyManager = KeyManager.getInstance();
        Key key = keyManager.getKey(multicastGroup);
        this.endPoint = keyManager.getEndPoint(multicastGroup);
        this.symmetricEncription = new SymmetricEncription(endPoint.getSea(), endPoint.getMode(), endPoint.getPadding(), key);
        this.integrity = new Integrity(endPoint.getInthash());
        this.authenticity = new Authenticity(endPoint.getMac(), key);
    }

    //Phase2
    public Security(EndPoint endPoint, Key key) throws Exception {
        this.endPoint = endPoint;
        this.symmetricEncription = new SymmetricEncription(endPoint.getSea(), endPoint.getMode(), endPoint.getPadding(), key);
        this.integrity = new Integrity(endPoint.getInthash());
        this.authenticity = new Authenticity(endPoint.getMac(), key);
    }

    public SymmetricEncription getSymmetricEncription() {
        return symmetricEncription;
    }

    public Integrity getIntegrity() {
        return integrity;
    }

    public Authenticity getAuthenticity() {
        return authenticity;
    }

    public byte[] getEndPointBytes() {
        return endPoint.getByteArray();
    }
}
