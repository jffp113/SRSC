package SecureProtocol.SecureSocket;

import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.SecureSocket.SMCPMessageProtocole.SMCPMessage;
import SecureProtocol.Security.Security;

import java.io.*;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.Key;

import static SecureProtocol.Utils.*;

public class SMCPSocket extends MulticastSocket {

    private final String sAttributes;
    private final String multicastGroup;
    private String peerId;

    private Security sec;
    private SMCPMessage smcpMessage;

    public SMCPSocket(String peerId, String group, int port, EndPoint endPoint, Key key) throws Exception {
        super(port);

        //PeerId iguais podiam dar replying pelo seqnum
        this.peerId = peerId + System.nanoTime() + Math.random();

        this.multicastGroup = group.substring(1) + ":" + port;
        this.sec = new Security(endPoint, key);
        sAttributes = base64Encode(sec.getIntegrity().getHash(sec.getEndPointBytes()));
        smcpMessage = new SMCPMessage(multicastGroup, sec, sAttributes, this.peerId);
    }

    @Override
    public void send(DatagramPacket p) throws IOException {
        byte[] smcpMessageData = smcpMessage.generateSMCPMessage(p.getData());
        p.setData(smcpMessageData);
        super.send(p);
    }

    @Override
    public void receive(DatagramPacket p) throws IOException {
        super.receive(p);
        byte[] buffer = p.getData();
        byte[] message = smcpMessage.verifyAndGetMessage(p.getData());
        System.arraycopy(message,0,buffer,0,message.length);
    }
}
