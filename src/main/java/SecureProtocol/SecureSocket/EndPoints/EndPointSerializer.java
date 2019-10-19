package SecureProtocol.SecureSocket.EndPoints;

public class EndPointSerializer {

    public String b64Key;
    public EndPoint endPoint;

    private static final String ATTRIBUTES_AS_STRING = "" +
            "%s\n" + //multicastGroup
            "%s\n" + //sid
            "%s\n" + //sea
            "%d\n" + //seaks
            "%s\n" + //mode
            "%s\n" + //padding
            "%s\n" + //inthash
            "%s\n" + //mac
            "%d\n" +  //makks
            "%s";     //Key

    public static String serializeToString(EndPoint e, String b64Key){
        return String.format(ATTRIBUTES_AS_STRING,
                e.getMulticastGroup(),
                e.getSid(),
                e.getSea(),
                e.getSeaks(),
                e.getMode(),
                e.getPadding(),
                e.getInthash(),
                e.getMac(),
                e.getMakks(),
                b64Key);
    }

    public static EndPointSerializer deserialize(String input){
        String[] is = input.split("\n");
        EndPointSerializer x = new EndPointSerializer();
        x.endPoint = new EndPoint(is[0], is[1], is[2], Integer.parseInt(is[3]), is[4], is[5], is[6], is[7], Integer.parseInt(is[8]));
        x.b64Key = is[9];
        return x;
    }
}
