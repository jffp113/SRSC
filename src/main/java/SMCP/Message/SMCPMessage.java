package SMCP.Message;

import SMCP.CIA.*;
import SMCP.CIA.Exceptions.*;

import java.io.*;
import java.security.Key;

import SMCP.Message.Exceptions.SMCPException;
import SMCP.XML.EndPoint;

public class SMCPMessage {

    private byte vId;
    private String sId;
    private byte smcpMsgType;
    private byte[] sAttributes;

    private Confidentiality confidenciality;
    private Integrity integrity;
    private Authenticity authenticity;
    private EndPoint endPoint;

    private String peerId;
    private int seqNr;

    public SMCPMessage(String peerId, EndPoint e, Key key) {

        confidenciality = new Confidentiality(e.getSea(), e.getSeaks(), e.getModes(), e.getPadding(), key);
        integrity = new Integrity(e.getInthash());
        authenticity = new Authenticity(e.getMac(), e.getMakks(), key);

        this.peerId = peerId;
        seqNr = 0;

        endPoint = e;

        vId = 0x01;
        sId = e.getSid();
        smcpMsgType = 0x01;
        sAttributes = sAttributes();

    }

    public byte[] generateSMCPMessage(byte[] message) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeByte(vId);
        dataStream.writeUTF(sId);
        dataStream.writeByte(smcpMsgType);
        dataStream.writeUTF(Utils.Base64Encode(sAttributes));
        dataStream.write(generateSecurePayLoad(message));
        dataStream.flush();

        dataStream.write(generateFastSecurePayLoadCheck(byteStream.toByteArray()));
        dataStream.flush();

        return byteStream.toByteArray();
    }

    private byte[] sAttributes(){
        return integrity.generateHash(endPoint.getEndPoint());
    }

    private byte[] generateSecurePayLoad(byte[] message) throws IOException{
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeUTF(peerId);
        dataStream.writeInt(seqNr);//TODO: Não entendo como funciona
        dataStream.writeInt(seqNr++);//TODO: Não entendo como funciona
        dataStream.write(message);
        dataStream.write(integrity.generateHash(message));
        dataStream.flush();

        byte[] payLoad = byteStream.toByteArray();
        byte[] securePaylLoad = confidenciality.encrypt(payLoad);
        int SizeOfPayload = securePaylLoad.length * 8; //to bits

        byteStream.reset();
        dataStream = new DataOutputStream(byteStream);

        dataStream.writeInt(SizeOfPayload);
        dataStream.write(securePaylLoad);
        dataStream.flush();

        return byteStream.toByteArray();
    }

    private byte[] generateFastSecurePayLoadCheck(byte[] SMCPMessage) {
        return authenticity.generateMac(SMCPMessage);
    }

    //------------------------------------------------------------------------
    //------------------------------------------------------------------------
    //------------------------------------------------------------------------

    public byte[] digestSMCPMessage_MAC(byte[] SMCPMessage_MAC) throws IOException {
        int macLength = authenticity.getMacSize();
        byte[] smcpMessage = new byte[SMCPMessage_MAC.length - macLength];
        byte[] mac = new byte[macLength];
        System.arraycopy(SMCPMessage_MAC, 0, smcpMessage, 0, smcpMessage.length);
        System.arraycopy(SMCPMessage_MAC, smcpMessage.length, mac, 0, macLength);

        authenticity.verifyMac(smcpMessage, mac);

        return digestAndGetSMCPMessage(smcpMessage);

    }

    private byte[] digestAndGetSMCPMessage(byte[] smcpMessage) throws IOException {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(smcpMessage, 0, smcpMessage.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        verifyIfActualEqualsToExpected(dataStream.readByte(), vId, "VID");
        verifyIfActualEqualsToExpected(dataStream.readUTF(), vId, "SID");
        verifyIfActualEqualsToExpected(dataStream.readByte(), smcpMsgType, "smcpMsgType");
        verifyIfActualEqualsToExpected(dataStream.readUTF(), sAttributes, "I");

        int sizeOfPayload = dataStream.readInt() / 8; //to bytes
        byte[] securePayLoad = new byte[sizeOfPayload];
        for(int i = 0; i < sizeOfPayload; i++)
            securePayLoad[i] = dataStream.readByte();

        byte[] message = digestPayLoad(securePayLoad);

        return message;

    }

    private byte[] digestPayLoad(byte[] securePayLoad) throws IOException {
        byte[] payLoad = confidenciality.decrypt(securePayLoad);
        ByteArrayInputStream byteStream = new ByteArrayInputStream(payLoad, 0, payLoad.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        dataStream.readUTF();//peerId //TODO: Não entendo como funciona
        dataStream.readInt();//seqNum //TODO: Não entendo como funciona
        dataStream.readInt();//RandomNounce //TODO: Não entendo como funciona

        int integrityControlLen = integrity.getHashLength();
        int messageLen = byteStream.available() - integrityControlLen;

        byte[] message = new byte[messageLen];
        byte[] IntegrityControl = new byte[integrityControlLen];

        for(int i = 0; i < messageLen; i++)
            message[i] = dataStream.readByte();

        for(int i = 0; i < integrityControlLen; i++)
            IntegrityControl[i] = dataStream.readByte();

        integrity.verifyInput_Hash(message, IntegrityControl);

        return message;

    }

    private <E> void verifyIfActualEqualsToExpected(E actual , E expected, String type){
        if(!actual.equals(expected)){
            switch (type) {
                case "C": //Confidentiality
                    throw new ConfidentialityException();
                case "I": //Integrity
                    throw new IntegrityException();
                case "A": //Authenticity
                    throw new AuthenticityException();
                default:
                    throw new SMCPException(type);
            }
        }
    }
}
