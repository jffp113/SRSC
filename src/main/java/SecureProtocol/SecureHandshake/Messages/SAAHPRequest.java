package SecureProtocol.SecureHandshake.Messages;

import SecureProtocol.SecureHandshake.Exception.NotAuthorizedException;
import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
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

    public void sendRequestToOutputStream(DataOutputStream out) throws Exception {
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
        genObjectsFromPayload(request,in);
        return request;
    }
    private static void genObjectsFromPayload(SAAHPRequest request,DataInputStream dataStream) throws Exception {
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

    public void verifySignatureAndThrowException() throws Exception {
        String message = header.serializeToString() + permCertificate;
        if(!signer.verifySignature(message, signatureBase64, certificate().getPublicKey()))
            throw new NotAuthorizedException("");
    }

    public Certificate certificate(){
        return cert;
    }
}
