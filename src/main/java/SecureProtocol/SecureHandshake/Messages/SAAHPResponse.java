package SecureProtocol.SecureHandshake.Messages;

import SecureProtocol.SecureHandshake.Exception.NotAuthorizedException;
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
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

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
    private Certificate cert;
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
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        //write header
        out.writeUTF(header.serializeToString());

        //write certificate
        String cert = CertificateUtil.getPermCertificateString();
        out.writeUTF(cert);

        SecretKey secretKey = KeyManager.genRandomKey("AES", 256);
        SymmetricEncription symm = new SymmetricEncription("AES","CBC","PKCS5Padding", secretKey);

        byte[] m2 = genMessage();
        byte[] hash = new Integrity("SHA512").getHash(m2);
        dataStream.write(hash);
        dataStream.write(m2);

        //Encrypted Message with Key
        String m2_hash = Utils.base64Encode(symm.encrypt(byteStream.toByteArray()));
        out.writeUTF(m2_hash);

        AssymetricEncription asymm = new AssymetricEncription();
        String keyEncryptedWithPublicKey = asymm.encript(secretKey.getEncoded(), publickey);

        out.writeUTF(keyEncryptedWithPublicKey);
        out.writeUTF(Signer.getInstace().doSign(cert + m2_hash + keyEncryptedWithPublicKey));
    }

    private byte[] genMessage() {
        String eps = EndPointSerializer.serializeToString(endpoint, Utils.base64Encode(publickey.getEncoded()));
        String nounce = System.nanoTime()+"";
        return (eps + "\n" + nounce).getBytes();
    }

    public static SAAHPResponse getResponseFromInputStream(DataInputStream in) throws Exception {
        SAAHPHeader header = SAAHPHeader.parseHeader(in.readUTF());
        String certAsString = in.readUTF();
        Certificate cert = CertificateUtil.parseCertificate(new ByteArrayInputStream(certAsString.getBytes()));

        String m2HashB64Encrypted = in.readUTF();
        byte[] m2_hash_Encrypted = Utils.base64Decode(m2HashB64Encrypted);
        String k_encrypted = in.readUTF();

        AssymetricEncription assymetricEncription = new AssymetricEncription();
        byte[] k = assymetricEncription.decript(k_encrypted, CertificateUtil.getPersonalPrivateKey());
        Key key = new SecretKeySpec(k, "AES");

        SymmetricEncription symmetricEncription = new SymmetricEncription("AES","CBC","PKCS5Padding", key);
        byte[] m2_hash = symmetricEncription.decrypt(m2_hash_Encrypted);

        Integrity integrity = new Integrity("SHA512");
        int hashSize = integrity.getHashSize();
        int m2Size = m2_hash.length - hashSize;

        ByteArrayInputStream byteStream = new ByteArrayInputStream(m2_hash);
        DataInputStream dataStream = new DataInputStream(byteStream);

        byte[] hash = new byte[hashSize];
        dataStream.read(hash);
        byte[] m2 = new byte[m2Size];
        dataStream.read(m2);

        byte[] tmp = integrity.getHash(m2);
        if(!Arrays.equals(integrity.getHash(m2),hash))
            throw new Exception();

        String[] m = new String(m2).split("\n");
        String nouce = m[10]; //TODO

        EndPointSerializer e = EndPointSerializer.deserialize(new String(m2));
        Key chatKey = new SecretKeySpec(Utils.base64Decode(e.b64Key), e.endPoint.getSea());

        SAAHPResponse response = new SAAHPResponse(e.endPoint, chatKey);
        response.header = header;
        response.cert = cert;

        verifySignatureAndThrowException(certAsString,m2HashB64Encrypted,k_encrypted,in.readUTF(),cert);
        return response;
    }

    public static SAAHPResponse createSuccessResponse(EndPoint endpoint, PublicKey key){
        SAAHPResponse s = new SAAHPResponse(endpoint, key);
        s.header = SAAHPHeader.createNewResponseHeader(SAAHPCode.ACCEPTED, RequestHandler.HANDLER_PROTOCOL_VERSION);
        return s;
    }

    public void verify() throws Exception{
        ((X509Certificate)this.cert).checkValidity();
    }

    private static void verifySignatureAndThrowException(String cert ,String m2_hash, String keyEncryptedWithPublicKey,
                                                  String signature, Certificate certificate) throws Exception {
        if(!Signer.getInstace().verifySignature(cert+m2_hash+keyEncryptedWithPublicKey,
                signature,certificate.getPublicKey()))
          throw new NotAuthorizedException("");
    }
}
