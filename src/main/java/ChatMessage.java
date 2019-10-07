public class ChatMessage {

    public final String MESSAGE_REGEX = "(?<FromPeerID>.*)\\|(?<SeqNr>.*)\\|(?<RandomNonce>.*)\\|(?<Message>.*)\\|(?<IntegrityControl>.*)";

    private String id;
    private int seqNumber;
    private String nouce;
    private String message;
    private String integrityControl;



    public ChatMessage(String id,int seqNumber,String nouce, String message,String integrityControl){
        this.id = id;
        this.seqNumber = seqNumber;
        this.nouce = nouce;
        this.message = message;
        this.integrityControl = integrityControl;
    }

    public byte[] serialize(){
        return null; //TODO
    }

    public static ChatMessage deserialize(byte[] messageAsBytes){
        return null; //TODO
    }



}
