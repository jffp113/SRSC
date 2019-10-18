package SecureProtocol.SecureSocket;

import SecureProtocol.SecureSocket.EndPoints.EndPoint;
import SecureProtocol.Security.Authenticity;
import SecureProtocol.Security.SymmetricEncription;
import SecureProtocol.Security.Integrity;
import SecureProtocol.SecureSocket.Exception.SMSCException;
import SecureProtocol.SecureSocket.KeyManagement.KeyManager;

import java.io.*;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.Key;
import java.util.*;
import static SecureProtocol.Utils.*;

public class SMSCSocket extends MulticastSocket {

    private static final String vid = "Version 6.0.75";
    private static final byte smcpMsgType = 0x01;

    public static final String VERSION_NOT_ACTUALIZED = "Not updated version";
    public static final String CHAT_SESSION_VIOLATED = "Chat Session Violated";
    public static final String SESSION_ATTRIBUTES_VIOLATED = "Session Attributes Violated";
    public static final String MESSAGE_TYPE_VIOLATED = "MessageTypeViolated";
    public static final String SECURE_PAYLOAD_VIOLATED = "Secure Payload Violated";
    public static final String INTEGRITY_CONTROL_VIOLATED = "Integrity Control Violated";

    private final String sAttributes;
    private final String sid;
    private String peerId;
    private int seqnum;
    private Map<String, Set<String  >> nouceMap;

    private KeyManager keyManager;
    private SymmetricEncription confidentiality;
    private Integrity integrity;
    private final Authenticity authenticity;

    private EndPoint endpoint;

    public SMSCSocket(String peerId,String group, int port) throws Exception {
        super(port);

        this.sid = group.substring(1) + ":" + port;
        this.keyManager = new KeyManager();
        endpoint = keyManager.getEndPoint(sid);

        Key key = keyManager.getKey(sid);

        //CIA
        this.confidentiality = new SymmetricEncription(endpoint.getSea(), endpoint.getMode(), endpoint.getPadding(), key);
        this.integrity = new Integrity(endpoint.getInthash());
        this.authenticity = new Authenticity(endpoint.getMac(), key);

        sAttributes = base64Encode(integrity.getHash(endpoint.getByteArray()));

        this.peerId = peerId;
        seqnum = 0;
        nouceMap = new HashMap<>(100);
    }

    @Override
    public void send(DatagramPacket p) throws IOException {
        byte[] finalPacket = genProtocolMessage(p);
        p.setData(finalPacket);
        super.send(p);
    }

    private byte[] genProtocolMessage(DatagramPacket p) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);
        byte[] securePayload = genSecurePayload(p);

        dataStream.writeUTF(vid);
        dataStream.writeUTF(sid);
        dataStream.writeByte(smcpMsgType);
        dataStream.writeUTF(sAttributes);
        dataStream.write(securePayload.length + authenticity.getMacSize());
        dataStream.write(authenticity.generateMac(securePayload));

        return byteStream.toByteArray();
    }

    private byte[] genSecurePayload(DatagramPacket p) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeUTF(peerId);
        dataStream.write(seqnum++);
        dataStream.writeUTF(generateNonce());
        dataStream.write(p.getLength());
        dataStream.write(p.getData());
        dataStream.writeUTF(base64Encode(integrity.getHash(p.getData())));

        return confidentiality.encrypt(byteStream.toByteArray());
    }

    @Override
    public void receive(DatagramPacket p) throws IOException {
        byte[] bufferTmp = new byte[p.getLength()];
        DatagramPacket tmp = new DatagramPacket(bufferTmp,0,bufferTmp.length);
        super.receive(tmp);

        p.setPort(tmp.getPort());
        p.setAddress(tmp.getAddress());

        byte[] buffer = p.getData();
        byte[] payload = deserializeProtocolMessage(tmp);
        System.arraycopy(payload,0,buffer,0,payload.length);
        p.setLength(payload.length);
    }

    private byte[] deserializeProtocolMessage(DatagramPacket p) throws IOException {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(p.getData(),0,p.getLength());
        DataInputStream dataStream = new DataInputStream(byteStream);

        verifyIfActualEqualsToExpected(dataStream.readUTF(), vid, VERSION_NOT_ACTUALIZED);
        verifyIfActualEqualsToExpected(dataStream.readUTF(), sid, CHAT_SESSION_VIOLATED);
        verifyIfActualEqualsToExpected(dataStream.readByte(), smcpMsgType, MESSAGE_TYPE_VIOLATED);
        verifyIfActualEqualsToExpected(dataStream.readUTF(), sAttributes, SESSION_ATTRIBUTES_VIOLATED);
        //Payload
        int sizeOfSecurePayload = dataStream.read();
        byte[] securePayload = new byte[sizeOfSecurePayload];
        dataStream.read(securePayload,0,sizeOfSecurePayload);

        securePayload = authenticity.verifyMac(securePayload); //TODO: Mudar isto para usar o verifyIfActualEqualsToExpected

        return deserializeSecurePayload(securePayload);
    }

    private byte[] deserializeSecurePayload(byte[] securePayload) throws IOException {
        byte[] payload = confidentiality.decrypt(securePayload);
        ByteArrayInputStream byteStream = new ByteArrayInputStream(payload,0,payload.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        String peerId = dataStream.readUTF();
        int seqNum = dataStream.read();
        String nouce = dataStream.readUTF();
        verifyUniqueNouce(nouce, peerId);

        byte[] message = new byte[dataStream.read()];
        dataStream.read(message);


        String integretyControl = dataStream.readUTF();
        verifyIfActualEqualsToExpected(base64Encode(integrity.getHash(message)),integretyControl, INTEGRITY_CONTROL_VIOLATED);
        return message;
    }

    private void verifyUniqueNouce(String nouce, String peerId) {
        Set<String> nouceS = this.nouceMap.get(peerId);
        if(nouceS == null)
            nouceS = new TreeSet<>();
        if(nouceS.contains(nouce))
            throw new SMSCException("Replaying Detection");
        nouceS.add(nouce);
    }

    private <E> void verifyIfActualEqualsToExpected(E actual , E expected, String message){
        if(!actual.equals(expected))
            throw new SMSCException(message);
    }

    private static String generateNonce(){
        String dateTimeString = Long.toString(new Date().getTime());
        byte[] nonceByte = dateTimeString.getBytes();
        return base64Encode(nonceByte);
    }


}
