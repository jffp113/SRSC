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

    public EndPoint(String multicastGroup, String sid, String sea, int seaks, String mode, String padding, String inthash, String mac, int makks) {
        this.multicastGroup = multicastGroup;
        this.sid = sid;
        this.sea = sea;
        this.seaks = seaks;
        this.mode = mode;
        this.padding = padding;
        this.inthash = inthash;
        this.mac = mac;
        this.makks = makks;
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
