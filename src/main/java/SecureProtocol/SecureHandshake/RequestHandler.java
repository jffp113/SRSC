package SecureProtocol.SecureHandshake;

import SecureProtocol.SecureHandshake.Exception.NotAuthorizedException;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPCode;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
import SecureProtocol.SecureHandshake.Messages.SAAHPRequest;
import SecureProtocol.SecureHandshake.Messages.SAAHPResponse;
import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.SecureSocket.EndPoints.XMLSecurityProperty;
import SecureProtocol.SecureSocket.Handler;
import sun.security.x509.CertificateX509Key;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.cert.X509Certificate;

public class RequestHandler implements Runnable{
    public static final String HANDLER_PROTOCOL_VERSION = "SAAHP/1.0";

    private final DataInputStream in;
    private final DataOutputStream out;
    private final Socket socket;

    public RequestHandler(Socket socket) throws IOException {
        this.socket = socket;
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
    }

    public void run(){
        final SAAHPRequest clientRequest;
        final SAAHPResponse serverResponse;
        try {
            clientRequest = SAAHPRequest.getRequestFromInputStream(in);
            X509Certificate certificate = (X509Certificate)clientRequest.certificate();
            clientRequest.verify();

            SAAHPHeader header = clientRequest.getHeader();
            String groupID = header.getChatID();
            EndPoint endpoint = XMLSecurityProperty.getEndPoints("SMCP.conf").get(groupID);
            SAAHPResponse.createSuccessResponse( endpoint, certificate.getPublicKey() ).sendResponseToOutputStream(out);

        } catch (NotAuthorizedException e){
            //Generate a Not Authorized response TODO
            SAAHPHeader.createNewResponseHeader(SAAHPCode.REJECTED, HANDLER_PROTOCOL_VERSION);
        } catch (Exception e) {
            //Generate a Internal Error Exception TODO
            SAAHPHeader.createNewResponseHeader(SAAHPCode.INTERNAL_ERROR,HANDLER_PROTOCOL_VERSION);
            e.printStackTrace();
        } finally {
            handlerResourcesClose();
        }
    }

    private void handlerResourcesClose(){
        try {
            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }




}
