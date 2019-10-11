package SMCP;
import SMCP.Message.SMCPMessage;
import SMCP.XML.EndPoint;
import SMCP.XML.XMLSecurityProperty;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import SMCP.KeyManager.KeyManager;
import java.net.SocketAddress;
import java.security.Key;

public class SMCPSockets extends MulticastSocket {

    private Key key;
    private EndPoint endPoint;

    private String peerId;


    public SMCPSockets(int port, String group, String fromPeerId) throws Exception {
        super(port);

        this.peerId = fromPeerId;

        String ipmc = group.substring(1, group.length())+":"+port; //tirar o "/" do inicio (ipmc:port)
        endPoint = XMLSecurityProperty.getEndPoint("SMCP.conf", ipmc);
        key = new KeyManager(endPoint).getKey(endPoint.getIp_port());
    }

    @Override
    public void send(DatagramPacket p) throws IOException {
        byte[] sMCPMessage = new SMCPMessage(peerId, endPoint, key).generateSMCPMessage(p.getData());
        p.setData(sMCPMessage);
        super.send(p);
    }

    @Override
    public synchronized void receive(DatagramPacket p) throws IOException {
        byte[] message = new SMCPMessage(peerId, endPoint, key).digestSMCPMessage_MAC(p.getData());
        p.setData(message);
        super.receive(p);
    }
}
