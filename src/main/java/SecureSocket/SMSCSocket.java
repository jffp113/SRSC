package SecureSocket;

import SecureSocket.Cripto.Confidenciality;
import SecureSocket.Cripto.Integrity;
import SecureSocket.Exception.SMSCException;
import SecureSocket.KeyManagement.KeyManager;

import java.io.*;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.util.*;

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
    private KeyManager manager;
    private Confidenciality confidenciality;
    private Integrity integrity;

    public SMSCSocket(SocketAddress bindaddr,String peerId,KeyManager manager,String group) throws Exception {
        super(bindaddr);
        this.chatsSession = bindaddr.toString();
        listSessionHash = genListSessionHash();
        this.manager = manager;
        this.peerId = peerId;
        seqNum = 0;
        nouceMap = new HashMap<>(100);
        id = group.substring(1);
        //CIA
        this.confidenciality = new Confidenciality(id,manager);
        this.integrity = new Integrity(this.manager.getEndPoint(id).getINTHASH());

    }

    public SMSCSocket(int port, String peerId,KeyManager manager,String group) throws Exception {
        this(new InetSocketAddress(port),peerId,manager,group);
    }

    //TODO
    private String genListSessionHash() {
        return "TODO";
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
        dataStream.write(securePayload.length);
        dataStream.write(securePayload);
        dataStream.writeUTF(genMac(securePayload));

        System.out.println(new String(Base64.getEncoder().encode(securePayload)));

        return byteStream.toByteArray();
    }

    private String genMac(byte[] securePayload) {
        return "todo"; //todo
    }

    private int getMacLenght(){
        return 4; //TODO
    }

    private int getHashSize(){
        return this.integrity.hashSize();
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
        dataStream.writeUTF(genRandomNonce());
        dataStream.write(p.getLength());
        dataStream.write(p.getData());
        dataStream.writeUTF(genIntegrityControl(p.getData()));

        return encrypt(byteStream.toByteArray());
    }

    private byte[] encrypt(byte[] toByteArray) {
        return confidenciality.encrypt(toByteArray);
    }

    private String genIntegrityControl(byte[] messagePayload) {
        return Base64.getEncoder().encodeToString(integrity.makeHash(messagePayload));
    }

    private String genRandomNonce() {
        return "TODO"; //TODO;
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

        verifyIfActualEqualsToExpected(dataStream.readUTF(),genMac(securePayload), SECURE_PAYLOAD_VIOLATED);

        return deserializeSecurePayload(securePayload);
    }

    private byte[] deserializeSecurePayload(byte[] securePayload) throws IOException {
        byte[] payload = decrypt(securePayload);
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
        Set<String> nouceAndSeq = this.nouceMap.get(peerId);
        String tmp = nouce + seqNum;
        if(nouceAndSeq == null)
            nouceAndSeq = new TreeSet<String>();

        if(nouceAndSeq.contains(tmp))
            throw new SMSCException("Replaying Detection");

        nouceAndSeq.add(tmp);
    }

    private <E> void verifyIfActualEqualsToExpected(E actual , E expected, String message){
        if(!actual.equals(expected)){
            throw new SMSCException(message);
        }
    }

    private byte[] decrypt(byte[] toByteArray) {
        return confidenciality.decrypt(toByteArray);
    }


}
