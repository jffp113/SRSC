package SecureProtocol.SecureSocket.EndPoints;

public class EndPointWithKey extends EndPoint{

    private String b64Key;

    public EndPointWithKey(String multicastGroup, String sid, String sea, int seaks, String mode, String padding, String inthash, String mac, int makks, String b64Key){
        super(multicastGroup, sid, sea, seaks, mode, padding, inthash, mac, makks);
        this.b64Key = b64Key;
    }

    public String getB64Key(){
        return b64Key;
    }
}
