package SecureSocket.Protocol;

import SecureSocket.Cripto.Integrity;
import SecureSocket.KeyManagement.KeyManager;
import SecureSocket.misc.EndPoint;

import java.io.*;
import java.security.NoSuchAlgorithmException;

public class SMCPMessage {

    public static final byte VID = 0x01;
    public static final byte SMCPMSGTYPE = 0x01;

    private byte vID;
    private String sID;
    private byte SMCPmsgType;
    private byte[] sAttributes;
    private int sizeOfSecurePayLoad;
    private PayLoadClass payLoad;
    private byte[] FastSecurePayLoadCheck;

    private EndPoint endPoint;


    private SMCPMessage(byte[] smcpMessage, KeyManager key) throws IOException, NoSuchAlgorithmException {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(smcpMessage,0,smcpMessage.length);
        DataInputStream dataStream = new DataInputStream(byteStream);

        this.vID = dataStream.readByte();
        Integrity.checkEquality(this.vID, VID);

        this.sID = dataStream.readUTF();
        this.endPoint = key.getEndPoint(sID);
        Integrity integrity = new Integrity(endPoint.getINTHASH());

        this.SMCPmsgType = dataStream.readByte();
        Integrity.checkEquality(this.SMCPmsgType, SMCPMSGTYPE);

        //this.sAttributes = dataStream.readNBytes(integrity.hashLength()); TODO
        integrity.compare_InputHash_hash(endPoint.getAttributes(), sAttributes);

        this.sizeOfSecurePayLoad = dataStream.readInt();
        //this.payLoad = new PayLoadClass(dataStream.readNBytes(sizeOfSecurePayLoad)); TODO



        //this.FastSecurePayLoadCheck = dataStream.readAllBytes(); TODO
    }


    private SMCPMessage(String sID, byte[] sAttributes, int sizeOfSecurePayLoad, byte[] securePayLoad, byte[] FastSecureMCheck) throws IOException {

    }

    public static SMCPMessage digestSMCPMessage(byte[] smcpMessage, KeyManager key) throws IOException, NoSuchAlgorithmException {
        return new SMCPMessage(smcpMessage, key);
    }

    public static SMCPMessage createNewSMCPMessage(String sID, byte[] sAttributes, int sizeOfSecurePayLoad, byte[] securePayLoad, byte[] FastSecureMCheck) throws IOException {
        return new SMCPMessage( sID, sAttributes, sizeOfSecurePayLoad, securePayLoad, FastSecureMCheck);
    }

}
