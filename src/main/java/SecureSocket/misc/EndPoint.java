package SecureSocket.misc;

public class EndPoint {

    private String IP_PORT;
    private String SID;
    private String SEA;
    private String SEAKS;
    private String MODES;
    private String PADDING;
    private String INTHASH;
    private String MAC;
    private String MAKKS;

    public EndPoint(String IP_PORT, String SID, String SEA, String SEAKS, String MODES, String PADDING, String INTHASH, String MAC, String MAKKS) {
        this.IP_PORT = IP_PORT;
        this.SID = SID;
        this.SEA = SEA;
        this.SEAKS = SEAKS;
        this.MODES = MODES;
        this.PADDING = PADDING;
        this.INTHASH = INTHASH;
        this.MAC = MAC;
        this.MAKKS = MAKKS;
    }

    public String getIP_PORT() {
        return IP_PORT;
    }

    public String getSID() {
        return SID;
    }

    public String getSEA() {
        return SEA;
    }

    public String getSEAKS() {
        return SEAKS;
    }

    public String getMODES() {
        return MODES;
    }

    public String getPADDING() {
        return PADDING;
    }

    public String getINTHASH() {
        return INTHASH;
    }

    public String getMAC() {
        return MAC;
    }

    public String getMAKKS() {
        return MAKKS;
    }

    public byte[] getAttributes() {
        //TODO: MELHORAR
        return SID.concat(SEA).concat(MODES).concat(PADDING).concat(INTHASH).concat(MAC).concat(MAKKS).getBytes();
    }
}
