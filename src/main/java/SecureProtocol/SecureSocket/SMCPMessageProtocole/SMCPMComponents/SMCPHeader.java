package SecureProtocol.SecureSocket.SMCPMessageProtocole.SMCPMComponents;

import SecureProtocol.Utils;

import java.io.*;

public class SMCPHeader {

    private static final String VID = "Version 6.0.75";
    private static final byte SMCP_MESSAGE_TYPE = 0x01;

    public static final String VERSION_NOT_ACTUALIZED = "[VID] Update to " + VID;
    public static final String CHAT_SESSION_VIOLATED = "[SID] Chat Session Violated";
    public static final String MESSAGE_TYPE_VIOLATED = "[SMCPMSGTYPE] Message type violated";
    public static final String SESSION_ATTRIBUTES_VIOLATED = "[SATTRIBUTES] Session attributes violated";

    private String sAttributes;
    private String multicastGroup;
    private byte[] headerBytes;

    public SMCPHeader(String multicastGroup, String sAttributes) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeUTF(VID);
        dataStream.writeUTF(multicastGroup);
        dataStream.writeByte(SMCP_MESSAGE_TYPE);
        dataStream.writeUTF(sAttributes);
        dataStream.flush();

        this.multicastGroup = multicastGroup;
        this.sAttributes = sAttributes;
        headerBytes = byteStream.toByteArray();
    }

    public byte[] getHeaderBytes() {
        return headerBytes;
    }

    public int getHeaderSize() {
        return headerBytes.length;
    }

    public void verifyHeader(byte[] receivedHeader) throws IOException {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(receivedHeader,0,receivedHeader.length);
        DataInputStream dataStream = new DataInputStream(byteStream);
        Utils.verify(dataStream.readUTF(), VID, VERSION_NOT_ACTUALIZED);
        Utils.verify(dataStream.readUTF(), multicastGroup, CHAT_SESSION_VIOLATED);
        Utils.verify(dataStream.readByte(), SMCP_MESSAGE_TYPE, MESSAGE_TYPE_VIOLATED);
        Utils.verify(dataStream.readUTF(), sAttributes, SESSION_ATTRIBUTES_VIOLATED);
    }

}
