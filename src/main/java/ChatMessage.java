public class ChatMessage {

    public final String MESSAGE_REGEX = "<(?<room>.*)>\\s*\u2028<SID_POS>(?<SID_POS>.*)</SID_POS>\\s*\n" +
                                            "<SEA_POS>(?<SEA_POS>.*)</SEA_POS>\\s*\n" +
                                            "<SEAKS_POS>(?<SEAKS_POS>.*)</SEAKS_POS>\\s*\n" +
                                            "<MODE>(?<MODE>.*)</MODE>\\s*\u2028<P ADDING>(?<P ADDING>.*)</P ADDING>\\s* \n" +
                                            "<INTHASH>(?<INTHASH>.*)</INTHASH>\\s* \n" +
                                            "<MAC>(?<MAC>.*)</MAC>\\s* \n" +
                                            "<MAKKS>(?<MAKKS>.*)</MAKKS>\\s* \n" +
                                            "</.*>\\s* \n";

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
