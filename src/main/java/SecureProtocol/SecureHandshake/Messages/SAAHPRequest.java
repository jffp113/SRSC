package SecureProtocol.SecureHandshake.Messages;

import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHHeader;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPProperties;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.*;
import java.security.cert.Certificate;
import static SecureProtocol.Utils.base64Encode;


public class SAAHPRequest {
    private SAAHHeader header;
    private byte[] payload;

    private Certificate cert;
    private String signatureBase64;
    private String permCertificate;

    private SAAHPRequest() {
        cert = null;
        signatureBase64 = null;
        permCertificate = null;
    }

    public SAAHPRequest(byte[] signature,Certificate cert,SAAHHeader header) throws Exception {
        this.header = header;
        this.cert = cert;
        signatureBase64 = base64Encode(signature);
        permCertificate = CertificateUtil.getPermCertificateAsString(cert);
    }

    public void sendRequestToOutputStream(DataOutputStream out) throws IOException {
        out.writeUTF(header.serializeToString());
        out.writeUTF("\n");
        out.writeUTF(permCertificate);
        out.writeUTF(signatureBase64);
    }

    public static SAAHPRequest getRequestFromInputStream(DataInputStream in) throws IOException {
        SAAHPRequest request = new SAAHPRequest();
        String headerString = in.readUTF();
        in.readUTF();
        request.header = SAAHHeader.parseHeader(headerString);
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

    public SAAHHeader getHeader() {
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
        cert = CertificateUtil.parseCertificates(new ByteArrayInputStream(permCertificate.getBytes()));
    }
}
