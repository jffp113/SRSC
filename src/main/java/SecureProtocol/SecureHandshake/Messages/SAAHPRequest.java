package SecureProtocol.SecureHandshake.Messages;

import SecureProtocol.SecureHandshake.Exception.NotAuthorizedException;
import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPProperties;
import SecureProtocol.Security.Signer;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.*;
import java.security.cert.Certificate;


public class SAAHPRequest {
    private SAAHPHeader header;

    private Certificate cert;
    private String signatureBase64;
    private String permCertificate;
    private Signer signer;

    private SAAHPRequest() {
        cert = null;
        signatureBase64 = null;
        permCertificate = null;
        signer = Signer.getInstace();
    }

    public SAAHPRequest(Certificate cert, SAAHPHeader header) throws Exception {
        this.header = header;
        this.cert = cert;
        signatureBase64 = null;
        permCertificate = CertificateUtil.getPermCertificateAsString(cert);
        signer = Signer.getInstace();
    }

    public void sendRequestToOutputStream(DataOutputStream out) throws IOException {
        String headerAsString = header.serializeToString();
        signatureBase64 = signer.doSign(headerAsString+permCertificate);
        out.writeUTF(headerAsString);
        out.writeUTF("\n");
        out.writeUTF(permCertificate);
        out.writeUTF(signatureBase64);
    }

    public static SAAHPRequest getRequestFromInputStream(DataInputStream in) throws Exception {
        SAAHPRequest request = new SAAHPRequest();
        String headerString = in.readUTF();
        in.readUTF();
        request.header = SAAHPHeader.parseHeader(headerString);
        byte[] payload = new byte[
                Integer.parseInt(request.header.getProperty(SAAHPProperties.CONTENT_LENGTH.toString()))];
        in.read(payload);
        genObjectsFromPayload(request,payload);
        return request;
    }
    private static void genObjectsFromPayload(SAAHPRequest request,byte[] payload) throws Exception {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(payload,0,payload.length);
        DataInputStream dataStream = new DataInputStream(byteStream);
        request.permCertificate = dataStream.readUTF();
        request.signatureBase64 = dataStream.readUTF();
        request.cert = CertificateUtil.parseCertificate(new ByteArrayInputStream(request.permCertificate.getBytes()));
    }

    public Certificate getCert() throws Exception {
        return cert;
    }

    public SAAHPHeader getHeader() {
        return header;
    }

    public byte[] getSignature() throws Exception {
        return Base64.decode(this.signatureBase64);
    }

    public void verifySignatureAndThrowException() throws NotAuthorizedException {
        if(!signer.verifySignature(certificate().getPublicKey()))
            throw new NotAuthorizedException("");
    }

    public Certificate certificate(){
        return cert;
    }
}
