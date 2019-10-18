package SecureProtocol.SecureHandshake.Messages;

import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPProperties;
import SecureProtocol.Security.Signer;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.*;
import java.security.cert.Certificate;


public class SAAHPRequest {
    private SAAHPHeader header;
    private byte[] payload;

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

    public static SAAHPRequest getRequestFromInputStream(DataInputStream in) throws IOException {
        SAAHPRequest request = new SAAHPRequest();
        String headerString = in.readUTF();
        in.readUTF();
        request.header = SAAHPHeader.parseHeader(headerString);
        request.payload = new byte[
                Integer.parseInt(request.header.getProperty(SAAHPProperties.CONTENT_LENGTH.toString()))];
        in.read(request.payload);

        return request;
    }

    public Certificate getCert() throws Exception {
        if(cert == null)
            genObjectsFromPayload();
        return cert;
    }

    public SAAHPHeader getHeader() {
        return header;
    }

    public byte[] getSignature() throws Exception {
        if(signatureBase64 == null)
            genObjectsFromPayload();
        return Base64.decode(this.signatureBase64);
    }

    public Certificate certificate() throws Exception{
        if(cert == null)
            genObjectsFromPayload();
        return cert;
    }

    private void genObjectsFromPayload() throws Exception {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(payload,0,payload.length);
        DataInputStream dataStream = new DataInputStream(byteStream);
        permCertificate = dataStream.readUTF();
        signatureBase64 = dataStream.readUTF();
        cert = CertificateUtil.parseCertificate(new ByteArrayInputStream(permCertificate.getBytes()));
    }
}
