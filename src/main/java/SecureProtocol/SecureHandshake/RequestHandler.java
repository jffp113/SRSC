package SecureProtocol.SecureHandshake;

import SecureProtocol.SecureHandshake.Exception.NotAuthorizedException;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
import SecureProtocol.SecureHandshake.Messages.SAAHPRequest;
import SecureProtocol.SecureHandshake.Messages.SAAHPResponse;
import SecureProtocol.SecureHandshake.ServerComponents.Credentials;
import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.SecureSocket.EndPoints.XMLSecurityProperty;
import SecureProtocol.SecureSocket.KeyManagement.KeyManager;
import SecureProtocol.Security.CertificateChain;

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
        try {
            clientRequest = SAAHPRequest.getRequestFromInputStream(in);
            CertificateChain certificate = (CertificateChain)clientRequest.certificate();
            clientRequest.verify();

            SAAHPHeader header = clientRequest.getHeader();
            String groupID = header.getChatID();
            EndPoint endpoint = KeyManager.getInstance().getEndPoint(groupID);
            SAAHPResponse
                    .createSuccessResponse(endpoint, certificate.getPublicKey(), clientRequest.getHeader().getPeerID())
                    .sendResponseToOutputStream(out,
                            Credentials.getUserCredencial(clientRequest.getHeader().getPeerID()), groupID);

        } catch (NotAuthorizedException e){
            sendDenied(out);
            e.printStackTrace();
        } catch (Exception e) {
            sendInternalError(out);
            e.printStackTrace();
        } finally {
            handlerResourcesClose();
        }
    }

    private void sendDenied(DataOutputStream out){
        try {
            SAAHPResponse.createDeniedResponse().sendResponseToOutputStream(out);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void sendInternalError(DataOutputStream out){
        try {
            SAAHPResponse.createInternalErrorResponse().sendResponseToOutputStream(out);
        } catch (Exception ex) {
            ex.printStackTrace();
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
