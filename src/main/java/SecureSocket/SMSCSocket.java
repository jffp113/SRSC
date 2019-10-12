package SecureSocket;

import SecureSocket.Security.Authenticity;
import SecureSocket.Security.Confidentiality;
import SecureSocket.Security.Integrity;
import SecureSocket.Exception.SMSCException;
import SecureSocket.KeyManagement.KeyManager;

import java.io.*;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.util.*;
import static SecureSocket.Utils.*;

public class SMSCSocket extends MulticastSocket {

    private static final String protocolID = "v1";
    private static final byte SMCPmsgType = 0x01;
    public static final String PROTOCOL_ID_VIOLATED = "Protocol ID violated";
    public static final String CHAT_SESSION_VIOLATED = "Chat Session Violated";
    public static final String SESSION_ATTRIBUTES_VIOLATED = "Session Attributes Violated";
    public static final String MESSAGE_TYPE_VIOLATED = "MessageTypeViolated";
    public static final String SECURE_PAYLOAD_VIOLATED = "Secure Payload Violated";
    public static final String INTEGRITY_CONTROL_VIOLATED = "Integrity Control Violated";

    private final String listSessionHash;

    private final String chatsSession;

    private String peerId;
    
    private int seqNum;

    private Map<String, Set<String  >> nouceMap;

    private String id;

    //CIA Context
    private KeyManager keyManager;
    private Confidentiality confidentiality;
    private Integrity integrity;
    private final Authenticity autencity;



    public SMSCSocket(int port,String peerId,String group) throws Exception {
        super(port);
        this.chatsSession = new InetSocketAddress(port).toString();
        this.keyManager = new KeyManager();
        this.peerId = peerId;
        seqNum = 0;
        nouceMap = new HashMap<>(100);
        id = group.substring(1);
        //CIA
        this.confidentiality = Confidentiality.getInstance(id, keyManager);
        this.integrity = Integrity.getInstance(this.keyManager.getEndPoint(id).getINTHASH());
        this.autencity = Authenticity.getInstance(id, keyManager);
        listSessionHash = genListSessionHash();
    }

    private String genListSessionHash() {
        return base64Encode(integrity.getHash(keyManager.getEndPoint(id).toString().getBytes()));
    }

    @Override
    public void send(DatagramPacket p) throws IOException {
        byte[] finalPacket = genProtocolMessage(p);
        p.setData(finalPacket);
        super.send(p);
    }

    /**
     * Gen entire protocol message
     * @param p
     * @return
     * @throws IOException
     */
    private byte[] genProtocolMessage(DatagramPacket p) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);
        byte[] securePayload = genSecurePayload(p);

        dataStream.writeUTF(protocolID);
        dataStream.writeUTF(chatsSession);
        dataStream.writeByte(SMCPmsgType);
        dataStream.writeUTF(listSessionHash);
        dataStream.write(securePayload.length + autencity.macSize());
        dataStream.write(autencity.makeMAC(securePayload));

        return byteStream.toByteArray();
    }

    private String genMac(byte[] securePayload) {
        return "todo"; //todo
    }

    /**
     * 
     * @param p
     * @return
     * @throws IOException
     */
    private byte[] genSecurePayload(DatagramPacket p) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeUTF(peerId);
        dataStream.write(seqNum++);
        dataStream.writeUTF(generateNonce());
        dataStream.write(p.getLength());
        dataStream.write(p.getData());
        dataStream.writeUTF(genIntegrityControl(p.getData()));

        return encrypt(byteStream.toByteArray());
    }

    private byte[] encrypt(byte[] toByteArray) {
        return confidentiality.encrypt(toByteArray);
    }

    private String genIntegrityControl(byte[] messagePayload) {
        return base64Encode(integrity.getHash(messagePayload));
    }

    @Override
    public void receive(DatagramPacket p) throws IOException {
        byte[] bufferTmp = new byte[p.getLength() * 2];
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


        verifyIfActualEqualsToExpected(dataStream.readUTF(),protocolID, PROTOCOL_ID_VIOLATED);
        verifyIfActualEqualsToExpected(dataStream.readUTF(),this.chatsSession, CHAT_SESSION_VIOLATED);
        verifyIfActualEqualsToExpected(dataStream.readByte(),this.SMCPmsgType, MESSAGE_TYPE_VIOLATED);
        verifyIfActualEqualsToExpected(dataStream.readUTF(),this.listSessionHash,SESSION_ATTRIBUTES_VIOLATED);
        //Payload
        int sizeOfSecurePayload = dataStream.read();
        byte[] securePayload = new byte[sizeOfSecurePayload];
        dataStream.read(securePayload,0,sizeOfSecurePayload);

        securePayload = autencity.checkMAC(securePayload);

        return deserializeSecurePayload(securePayload);
    }

    private byte[] deserializeSecurePayload(byte[] securePayload) throws IOException {
        byte[] payload = confidentiality.decrypt(securePayload);
        ByteArrayInputStream byteStream = new ByteArrayInputStream(payload,0,payload.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        String peerId = dataStream.readUTF();
        int seqNum = dataStream.read();
        String nouce = dataStream.readUTF();
        verifyUniqueNouce(nouce,seqNum,peerId);

        byte[] message = new byte[dataStream.read()];
        dataStream.read(message);


        String integretyControl = dataStream.readUTF();
        verifyIfActualEqualsToExpected(genIntegrityControl(message),integretyControl, INTEGRITY_CONTROL_VIOLATED);
        return message;
    }

    private void verifyUniqueNouce(String nouce, int seqNum, String peerId) {
        Set<String> nouceS = this.nouceMap.get(peerId);

        if(nouceS == null)
            nouceS = new TreeSet<String>();

        if(nouceS.contains(nouce))
            throw new SMSCException("Replaying Detection");

        nouceS.add(nouce);
    }

    private <E> void verifyIfActualEqualsToExpected(E actual , E expected, String message){
        if(!actual.equals(expected)){
            throw new SMSCException(message);
        }
    }

    private static String generateNonce(){
        String dateTimeString = Long.toString(new Date().getTime());
        byte[] nonceByte = dateTimeString.getBytes();
        return base64Encode(nonceByte);
    }


}
