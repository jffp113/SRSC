package SecureProtocol.SecureSocket.SMCPMessageProtocole;

import SecureProtocol.SecureSocket.SMCPMessageProtocole.Exception.SMCPException;
import SecureProtocol.SecureSocket.SMCPMessageProtocole.SMCPMComponents.SMCPHeader;
import SecureProtocol.SecureSocket.SMCPMessageProtocole.SMCPMComponents.SecurePayLoad;
import SecureProtocol.Security.Security;
import SecureProtocol.Utils;

import java.io.*;
import java.util.*;

public class SMCPMessage {

    public static final String MESSAGE_HASH_VIOLATED = "[MESSAGE HASH] Integrity Violated";
    public static final String REPLYING_SEQNUM = "[SEQNUM] Replaying Detection";
    public static final String REPLYING_NOUCE = "[NOUCE] Replaying Detection";
    public static final String MAC_VIOLATED = "[MAC] Violated.";

    private String multicastGroup;
    private Security sec;
    private String peerID;
    private SMCPHeader header;
    private int seqnum;
    private Map<String, Integer> seqnumMap;
    private Map<String, Set<Long>> nonceMap;

    public SMCPMessage(String multicastGroup, Security sec, String sAttributes, String peedID) throws IOException{
        this.multicastGroup = multicastGroup;
        this.sec = sec;
        this.peerID = peedID;
        header = new SMCPHeader(multicastGroup, sAttributes);
        seqnumMap = new HashMap<>(100);
        nonceMap = new HashMap<>(100);
        seqnum = 0;
    }

    public byte[] generateSMCPMessage(byte[] message) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.write(header.getHeaderBytes());

        byte[] securePayLoad = SecurePayLoad.generateSecurePayLoad(message, peerID, seqnum++, sec);
        dataStream.writeInt(securePayLoad.length);
        dataStream.write(securePayLoad);
        dataStream.flush();

        byte[] smcpMessage = byteStream.toByteArray();
        byte[] mac = sec.getAuthenticity().generateMac(smcpMessage);

        byteStream.reset();
        dataStream.writeUTF(Utils.base64Encode(smcpMessage));
        dataStream.writeUTF(Utils.base64Encode(mac));
        return byteStream.toByteArray();
    }

    public byte[] verifyAndGetMessage(byte[] smcpMessage_mac) throws IOException {
        //FastSecurePayLoadCheck
        byte[] smcpMessage = verifyMAC(smcpMessage_mac);

        ByteArrayInputStream byteStream = new ByteArrayInputStream(smcpMessage,0,smcpMessage.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        //Header
        byte[] headerBytes = new byte[header.getHeaderSize()];
        dataStream.read(headerBytes);
        header.verifyHeader(headerBytes);

        //SecurePayload
        int sizeOfSecurePayload = dataStream.readInt();
        byte[] securePayload = new byte[sizeOfSecurePayload];
        dataStream.read(securePayload);

        //PayLoad
        return deserializeSecurePayLoad(sec.getSymmetricEncription().decrypt(securePayload));
    }

    public byte[] deserializeSecurePayLoad(byte[] payLoad) throws IOException {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(payLoad,0,payLoad.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        //FromPeedId
        String fromPeerId = dataStream.readUTF();

        //seqnum
        verifySeqNum(dataStream.readInt(), fromPeerId);

        //nonce
        verifyUniqueNonce(dataStream.readLong(), fromPeerId);

        //message
        byte[] message = Utils.base64Decode(dataStream.readUTF());

        //integrityControl
        String b64MessageHash = Utils.base64Encode(sec.getIntegrity().getHash(message));
        String integrityControl = dataStream.readUTF();
        Utils.verify(b64MessageHash, integrityControl, MESSAGE_HASH_VIOLATED);
        return message;
    }

    private void verifySeqNum(int seqnum, String fromPeerId) {

        Integer atualSeNum = this.seqnumMap.get(fromPeerId);
        if(atualSeNum == null)
            seqnumMap.put(fromPeerId, seqnum);
        else{
            if(atualSeNum.intValue() == seqnum - 1)
                seqnumMap.replace(fromPeerId, seqnum);
            else throw new SMCPException(REPLYING_SEQNUM);
        }
    }

    private void verifyUniqueNonce(Long nonce, String fromPeerId) {
        Set<Long> nonceS = this.nonceMap.get(fromPeerId);
        if(nonceS == null)
            nonceS = new TreeSet<>();
        if(nonceS.contains(nonce))
            throw new SMCPException(REPLYING_NOUCE);
        nonceS.add(nonce);
    }

    private byte[] verifyMAC(byte[] smcpMessage_mac) throws IOException {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(smcpMessage_mac,0,smcpMessage_mac.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        byte[] smcpMessage = Utils.base64Decode(dataStream.readUTF());
        String b64smcpMessageMAC = Utils.base64Encode(sec.getAuthenticity().generateMac(smcpMessage));
        String b64MAC = dataStream.readUTF();
        Utils.verify(b64smcpMessageMAC, b64MAC, MAC_VIOLATED);
        return smcpMessage;
    }


}
