package SMCP.XML;

public class EndPoint {

    private String ip_port;
    private String sid;
    private String sea;
    private int seaks;
    private String modes;
    private String padding;
    private String inthash;
    private String mac;
    private int makks;

    public EndPoint(String ip_port, String sid, String sea, String seaks, String modes, String padding, String inthash, String mac, String makks) {
        this.ip_port = ip_port;
        this.sid = sid;
        this.sea = sea;
        this.seaks = Integer.parseInt(seaks);;
        this.modes = modes;
        this.padding = padding;
        this.inthash = inthash;
        this.mac = mac;
        this.makks = Integer.parseInt(makks);	;
    }

    public String getIp_port() {
        return ip_port;
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

    public String getModes() {
        return modes;
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

    public byte[] getEndPoint(){
        String endPoint = (sid + sea + seaks + modes + padding + inthash + mac + makks);
        return endPoint.getBytes();
    }
}
