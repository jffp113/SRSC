package SecureProtocol.SecureSocket.EndPoints;

public class EndPoint {

    private static final String ATTRIBUTES_AS_STRING = "" +
            "%s" + //multicastGroup
            "%s" + //sid
            "%s" + //sea
            "%s" + //seaks
            "%s" + //mode
            "%s" + //padding
            "%s" + //inthash
            "%s" + //mac
            "%s";  //makks

    private String multicastGroup;
    private String sid;
    private String sea;
    private int seaks;
    private String mode;
    private String padding;
    private String inthash;
    private String mac;
    private int makks;

    public EndPoint(String IP_PORT, String SID, String SEA, int SEAKS, String MODES, String PADDING, String INTHASH, String MAC, int MAKKS) {
        this.multicastGroup = IP_PORT;
        this.sid = SID;
        this.sea = SEA;
        this.seaks = SEAKS;
        this.mode = MODES;
        this.padding = PADDING;
        this.inthash = INTHASH;
        this.mac = MAC;
        this.makks = MAKKS;
    }

    public String getMulticastGroup() {
        return multicastGroup;
    }

    public String getSid() {
        return sid;
    }

    public String getSea() {
        return sea;
    }

    public int getSeaks() {
        return seaks;
    }

    public String getMode() {
        return mode;
    }

    public String getPadding() {
        return padding;
    }

    public String getInthash() {
        return inthash;
    }

    public String getMac() {
        return mac;
    }

    public int getMakks() {
        return makks;
    }

    public byte[] getByteArray() {
        return String.format(ATTRIBUTES_AS_STRING, multicastGroup, sid, sea, seaks, mode, padding, inthash, mac, makks).getBytes();
    }
}
