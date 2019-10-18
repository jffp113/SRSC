package SecureProtocol.SecureHandshake.Messages.Components;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SAAHPHeader {
    private static final String PROPERTIES_REGEX = "(.*):\\s*(.*)";
    private static final String REQUEST_HEADER_REGEX = "^(.*) (.*)/(.*) (SAAH/.*)\\n([\\S+\\s]*)$";
    private static final String RESPONSE_HEADER_REGEX = "^(SAAH/.+) (\\d+.*)\\n([\\S+\\s]*)$";


    public static final int INITIAL_CAPACITY = 20;

    private Map<String,String> headerProperties;

    //Global
    private String version;

    //Request
    private boolean isRequest;
    private String method;
    private String chatID;
    private String peerID;

    //Response
    private SAAHPCode code;

    private SAAHPHeader() {
        this.headerProperties = new HashMap<>(INITIAL_CAPACITY);
    }

    private SAAHPHeader(String method , String chatID, String peerID, String version){
        this.headerProperties = new HashMap<>(INITIAL_CAPACITY);
        isRequest = true;
        this.method = method;
        this.chatID = chatID;
        this.peerID = peerID;
        this.version = version;
    }

    private SAAHPHeader(SAAHPCode code, String version){
        this.headerProperties = new HashMap<>(INITIAL_CAPACITY);
        isRequest = false;
        this.code = code;
        this.version = version;
    }

    public static SAAHPHeader createNewResponseHeader(SAAHPCode code, String version){
        return new SAAHPHeader(code,version);
    }

    public static SAAHPHeader createNewRequestHeader(String method , String chatID, String peerID, String version){
        return new SAAHPHeader(method , chatID, peerID, version);
    }
    private static final Pattern propertyMatcher = Pattern.compile(PROPERTIES_REGEX);
    private static final Pattern globalRequestHeaderMatcher = Pattern.compile(REQUEST_HEADER_REGEX);
    private static final Pattern globalResponseHeaderMatcher = Pattern.compile(RESPONSE_HEADER_REGEX);

    public static SAAHPHeader parseHeader(String headerString){
        SAAHPHeader headerResult = new SAAHPHeader();

        Matcher requestMatcher = globalRequestHeaderMatcher.matcher(headerString);
        if(requestMatcher.matches()){
            parseRequest(headerResult,requestMatcher);
        }else{
            Matcher responseMatcher = globalResponseHeaderMatcher.matcher(headerString);
            parseResponse(headerResult,responseMatcher);
        }

        return headerResult;
    }

    public String serializeToString(){
        StringBuilder builder = new StringBuilder();
        if(isRequest){
            builder.append(String.format("%s %s/%s %s",method,chatID,peerID,version));
        }else{
            builder.append(String.format("%s %s",version, code));
        }

        for(Map.Entry<String,String> entry: headerProperties.entrySet()){
            builder.append(String.format("%s: %s",entry.getKey(),entry.getValue()));
        }

        return builder.toString();
    }

    private static void parseRequest(SAAHPHeader headerResult, Matcher matcher){
        headerResult.method = matcher.group(1);
        headerResult.chatID = matcher.group(2);
        headerResult.peerID = matcher.group(3);
        headerResult.version = matcher.group(4);
        parseProperties(headerResult,matcher.group(5));
    }


    private static void parseResponse(SAAHPHeader headerResult, Matcher matcher){
        headerResult.version = matcher.group(1);
        String codeAsString = matcher.group(2);
        headerResult.code = SAAHPCode.valueOf(codeAsString);
        parseProperties(headerResult,matcher.group(4));
    }

    private static void parseProperties(SAAHPHeader headerResult, String propertiesAsString) {
        Matcher m = propertyMatcher.matcher(propertiesAsString);
        while(m.find()){
            headerResult.headerProperties.put(m.group(1),m.group(2));
        }
    }

    public String getProperty(String prop){
        return this.headerProperties.get(prop);
    }

    public String getChatID() {
        return chatID;
    }

    public SAAHPCode getCode() {
        return this.code;
    }

    public String getMethod() {
        return method;
    }

    public String getPeerID() {
        return peerID;
    }

    public String getVersion() {
        return version;
    }

    public void addNewProperty(String key, String value){
        this.headerProperties.put(key,value);
    }
}
