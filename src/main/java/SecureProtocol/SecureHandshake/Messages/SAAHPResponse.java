package SecureProtocol.SecureHandshake.Messages;

import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPCode;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
import SecureProtocol.SecureHandshake.RequestHandler;
import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.SecureSocket.EndPoints.EndPointSerializer;
import SecureProtocol.SecureSocket.KeyManagement.KeyManager;
import SecureProtocol.Security.*;
import SecureProtocol.Utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class SAAHPResponse {

    public EndPoint getEndpoint() {
        return endpoint;
    }

    public Key getKey() {
        return key;
    }

    private SAAHPHeader header;
    private EndPoint endpoint;
    private PublicKey publickey;
    private Key key;

    private SAAHPResponse(EndPoint endpoint, PublicKey publickey){
        this.header = null;
        this.endpoint = endpoint;
        this.publickey = publickey;
    }

    private SAAHPResponse(EndPoint endpoint, Key key){
        this.header = null;
        this.endpoint = endpoint;
        this.publickey = null;
        this.key = key;
    }

    public void sendResponseToOutputStream(DataOutputStream out) throws Exception {
        //TODO
        String cert = CertificateUtil.getPermCertificateString();
        SecretKey secretKey = KeyManager.genRandomKey("AES", 256);
        SymmetricEncription symm = new SymmetricEncription("AES","CBC","PKCS5Padding", secretKey);

        byte[] m2 = genMessage();
        byte[] hash = new Integrity("SHA512").getHash(m2);
        byte[] m2_hash = new byte[m2.length + hash.length];

        System.arraycopy(m2, 0, m2_hash, 0, m2.length);
        System.arraycopy(hash, 0, m2_hash, m2.length, m2_hash.length);

        String x = Utils.base64Encode(symm.encrypt(m2_hash));

        AssymetricEncription asymm = new AssymetricEncription();
        String y = asymm.encript(secretKey.getEncoded(), publickey);

        String sign = Signer.getInstace().doSign(cert + x + y);

        out.writeUTF(header.serializeToString());
        out.writeUTF(cert);
        out.writeUTF(x);
        out.writeUTF(y);
        out.writeUTF(sign);
    }

    private byte[] genMessage() {
        String eps = EndPointSerializer.serializeToString(endpoint, Utils.base64Encode(publickey.getEncoded()));
        String nounce = System.nanoTime()+"";
        return (eps + "\n" + nounce).getBytes();
    }

    public static SAAHPResponse getResponseFromInputStream(DataInputStream in) throws Exception {
        SAAHPHeader header = SAAHPHeader.parseHeader(in.readUTF());
        Certificate cert = CertificateUtil.parseCertificate(new ByteArrayInputStream(in.readUTF().getBytes()));
        byte[] _m2_hash_ = Utils.base64Decode(in.readUTF());
        String _k_ = in.readUTF();

        AssymetricEncription assym = new AssymetricEncription();
        byte[] k = assym.decript(_k_, CertificateUtil.getPersonalPrivateKey());
        Key key = new SecretKeySpec(k, "AES");

        SymmetricEncription symm = new SymmetricEncription("AES","CBC","PKCS5Padding", key);
        symm.decrypt(_m2_hash_);

        Integrity integrity = new Integrity("SHA512");
        int hashSize = integrity.getHashSize();
        int m2Size = _m2_hash_.length - hashSize;

        byte[] hash = new byte[hashSize];
        byte[] m2 = new byte[m2Size];

        System.arraycopy(_m2_hash_,0, m2, 0, m2Size);
        System.arraycopy(_m2_hash_, m2Size, hash, 0, hashSize);

        if(!integrity.getHash(m2).equals(hash))
            throw new Exception();

        String[] m = new String(m2).split("\n");
        String eps = m[0];
        String nouce = m[1];

        EndPointSerializer e = EndPointSerializer.deserialize(eps);
        Key chatKey = new SecretKeySpec(Utils.base64Decode(e.b64Key), e.endPoint.getSea());

        return new SAAHPResponse(e.endPoint, chatKey);
    }

    public static SAAHPResponse createSuccessResponse(EndPoint endpoint, PublicKey key){
        SAAHPResponse s = new SAAHPResponse(endpoint, key);
        s.header = SAAHPHeader.createNewResponseHeader(SAAHPCode.ACCEPTED, RequestHandler.HANDLER_PROTOCOL_VERSION);
        return s;
    }
}
