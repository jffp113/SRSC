package SecureProtocol.SecureHandshake;

import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPCode;
import SecureProtocol.SecureHandshake.Messages.Components.SAAHPHeader;
import SecureProtocol.SecureHandshake.Messages.SAAHPRequest;
import SecureProtocol.SecureHandshake.Messages.SAAHPResponse;
import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.Security.Encription.Integrity;
import SecureProtocol.Utils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.Key;

public class Client {

    private final int port;
    private final String userPassword;
    private String peerID;
    private String multichatGroup;

    private Socket socket;
    DataOutputStream out;
    DataInputStream in;

    private EndPoint endpoint;
    private Key key;

    public Client(String peerID, String userPassword, String multichatGroup , int port) throws Exception {
        this.userPassword = userPassword;
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

    public void getEndPoinsAndKeyFromSAAHPServer() throws Exception {
        SAAHPRequest req = new SAAHPRequest(CertificateUtil.getPersonalCertificate(),
                SAAHPHeader.createNewRequestHeader("GETINFO", multichatGroup.substring(1) + ":"
                        + port, peerID, "SAAHP/1.0"));

        req.sendRequestToOutputStream(out);

        SAAHPResponse res = SAAHPResponse.getResponseFromInputStream(in,
                Utils.base64Encode(new Integrity("SHA512").getHash(userPassword.getBytes())));

        if(!res.getHeader().getCode().equals(SAAHPCode.ACCEPTED)){
            throw new Exception(res.getHeader().getCode().toString());
        }

        res.verify();

        this.endpoint = res.getEndpoint();
        this.key = res.getKey();
    }

}
