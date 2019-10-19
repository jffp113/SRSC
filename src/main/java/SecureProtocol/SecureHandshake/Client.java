package SecureProtocol.SecureHandshake;

import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
import SecureProtocol.SecureHandshake.Messages.SAAHPRequest;
import SecureProtocol.SecureHandshake.Messages.SAAHPResponse;
import SecureProtocol.SecureSocket.EndPoints.EndPoint;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Key;

public class Client {

    private final int port;
    private String peerID;
    private String multichatGroup;

    private Socket socket;
    DataOutputStream out;
    DataInputStream in;

    private EndPoint endpoint;
    private Key key;

    public Client(String peerID, String multichatGroup , int port) throws Exception {
        this.peerID = peerID;
        this.multichatGroup = multichatGroup;
        this.socket = new Socket("localhost", 6789);
        this.port = port;
        out = new DataOutputStream(socket.getOutputStream());
        in = new DataInputStream(socket.getInputStream());
    }

    public EndPoint getEndPoint(){
        return endpoint;
    }

    public Key getKey(){
        return key;
    }

    public void getEndPoinsAndKeyFromSAAHServer() throws Exception {
        SAAHPRequest req = new SAAHPRequest(CertificateUtil.getPersonalCertificate(),
                SAAHPHeader.createNewRequestHeader("GETINFO", multichatGroup.substring(1) + ":"
                        + port, peerID, "SAAH/1.0"));

        req.sendRequestToOutputStream(out);

        SAAHPResponse res = SAAHPResponse.getResponseFromInputStream(in);

        this.endpoint = res.getEndpoint();
        this.key = res.getKey();
    }
}
