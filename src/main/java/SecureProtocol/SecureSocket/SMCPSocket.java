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

    //Phase 1
    public SMCPSocket(String peerId, String group, int port) throws Exception {
        super(port);
        //PeerId iguais podiam dar replying pelo seqnum
        this.peerId = peerId + System.nanoTime() + Math.random();
        this.multicastGroup = group.substring(1) + ":" + port;

        this.sec = new Security(multicastGroup);
        sAttributes = base64Encode(sec.getIntegrity().getHash(sec.getEndPointBytes()));
        smcpMessage = new SMCPMessage(multicastGroup, sec, sAttributes, this.peerId);
    }

    //Phase 2
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
        byte[] bufferTmp = new byte[p.getLength()];
        DatagramPacket tmp = new DatagramPacket(bufferTmp,0,bufferTmp.length);
        super.receive(tmp);

        p.setPort(tmp.getPort());
        p.setAddress(tmp.getAddress());

        byte[] buffer = p.getData();
        byte[] payload = smcpMessage.verifyAndGetMessage(tmp.getData());
        System.arraycopy(payload,0,buffer,0,payload.length);
        p.setLength(payload.length);
    }


}
