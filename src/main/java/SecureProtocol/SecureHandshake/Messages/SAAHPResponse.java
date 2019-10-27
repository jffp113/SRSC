package SecureProtocol.SecureHandshake.Messages;

import SecureProtocol.SecureHandshake.Exception.NotAuthorizedException;
import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPCode;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
import SecureProtocol.SecureHandshake.RequestHandler;
import SecureProtocol.SecureHandshake.ServerComponents.Credentials;
import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.SecureSocket.EndPoints.EndPointSerializer;
import SecureProtocol.SecureSocket.KeyManagement.KeyManager;
import SecureProtocol.Security.CertificateChain;
import SecureProtocol.Security.Encription.AssymetricEncription;
import SecureProtocol.Security.Encription.Integrity;
import SecureProtocol.Security.Encription.Signer;
import SecureProtocol.Security.Encription.SymmetricEncription;
import SecureProtocol.Security.Rekeying;
import SecureProtocol.Utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class SAAHPResponse {

    private final static String ALG = "AES";
    private final static int SIZE = 256;
    private final static String MODE = "CBC";
    private final static String PADDING = "PKCS5Padding";
    private final static String HASH_ALG = "SHA512";

    private SAAHPHeader header;
    private EndPoint endpoint;
    private PublicKey publickey;
    private Certificate cert;
    private Key key;
    private String user;

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
        //write header
        out.writeUTF(header.serializeToString());
    }

    public void sendResponseToOutputStream(DataOutputStream out, String credencials, String chatID) throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        //write header
        out.writeUTF(header.serializeToString());

        //write certificate
        String cert = CertificateUtil.getPermCertificateString();
        out.writeUTF(cert);

        SecretKey secretKey = KeyManager.genRandomKey(ALG, SIZE);
        SymmetricEncription symm = new SymmetricEncription(ALG,MODE,PADDING,
                Rekeying.xorKeyWithHash(credencials,secretKey));

        byte[] m2 = genMessage(chatID);
        byte[] hash = new Integrity(HASH_ALG).getHash(m2);
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

    private byte[] genMessage(String chatID) throws Exception {
        byte[] chatKey = KeyManager.getInstance().getKey(chatID).getEncoded();
        String eps = EndPointSerializer.serializeToString(endpoint, Utils.base64Encode(chatKey));
        String nonce = System.nanoTime()+"";
        return (eps + "\n" + nonce).getBytes();
    }

    public static SAAHPResponse getResponseFromInputStream(DataInputStream in,String userPasswordHasHash) throws Exception {
        SAAHPHeader header = SAAHPHeader.parseHeader(in.readUTF());

        if(!header.getCode().equals(SAAHPCode.ACCEPTED)) {
            SAAHPResponse response = new SAAHPResponse(null,null);
            response.header = header;
            return response;
        }
        String certAsString = in.readUTF();
        Certificate cert = CertificateUtil.parseCertificates(new ByteArrayInputStream(certAsString.getBytes()));

        String m2HashB64Encrypted = in.readUTF();
        byte[] m2_hash_Encrypted = Utils.base64Decode(m2HashB64Encrypted);
        String k_encrypted = in.readUTF();

        AssymetricEncription assymetricEncription = new AssymetricEncription();
        byte[] k = assymetricEncription.decript(k_encrypted, CertificateUtil.getPersonalPrivateKey());
        Key key = new SecretKeySpec(k, ALG);

        SymmetricEncription symmetricEncription = new SymmetricEncription(ALG,MODE,PADDING,
                Rekeying.xorKeyWithHash(userPasswordHasHash,key));
        byte[] m2_hash = symmetricEncription.decrypt(m2_hash_Encrypted);

        Integrity integrity = new Integrity(HASH_ALG);
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


    public static SAAHPResponse createSuccessResponse(EndPoint endpoint, PublicKey key,String user){
        SAAHPResponse s = new SAAHPResponse(endpoint, key);
        s.user = user;
        s.header = SAAHPHeader.createNewResponseHeader(SAAHPCode.ACCEPTED, RequestHandler.HANDLER_PROTOCOL_VERSION);
        return s;
    }

    public static SAAHPResponse createDeniedResponse(){
        SAAHPResponse s = new SAAHPResponse(null, null);
        s.header = SAAHPHeader.createNewResponseHeader(SAAHPCode.REJECTED, RequestHandler.HANDLER_PROTOCOL_VERSION);
        return s;
    }
    public static SAAHPResponse createInternalErrorResponse(){
        SAAHPResponse s = new SAAHPResponse(null, null);
        s.header = SAAHPHeader.createNewResponseHeader(SAAHPCode.INTERNAL_ERROR, RequestHandler.HANDLER_PROTOCOL_VERSION);
        return s;
    }

    public void verify(){
        ((CertificateChain)this.cert).verify("Leaf"); //TODO
    }

    public SAAHPHeader getHeader() {
        return header;
    }

    private static void verifySignatureAndThrowException(String cert , String m2_hash, String keyEncryptedWithPublicKey,
                                                         String signature, Certificate certificate) throws Exception {
        if(!Signer.getInstace().verifySignature(cert+m2_hash+keyEncryptedWithPublicKey,
                signature,certificate.getPublicKey()))
          throw new NotAuthorizedException("");
    }

    public EndPoint getEndpoint() {
        return endpoint;
    }

    public Key getKey() {
        return key;
    }
}
