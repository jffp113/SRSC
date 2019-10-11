package SMCP.XML;

import SMCP.XML.Exceptions.EndPointException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class XMLSecurityProperty {

    public static final String XML_REGEX = "" +
            "<(.*)>\\s*\\n*" +
            "<SID>(.*)<\\/SID>\\s*\\n*" +
            "<SEA>(.*)<\\/SEA>\\s*\\n*" +
            "<SEAKS>(.*)<\\/SEAKS>\\s*\\n*" +
            "<MODE>(.*)<\\/MODE>\\s*\\n*" +
            "<PADDING>(.*)<\\/PADDING>\\s*\\n*" +
            "<INTHASH>(.*)<\\/INTHASH>\\s*\\n*" +
            "<MAC>(.*)<\\/MAC>\\s*\\n*" +
            "<MAKKS>(.*)<\\/MAKKS>\\s*\\n*" +
            "<\\/.*>\\s*\\n*";

    private static final int IP_PORT_POS =  1;
    private static final int SID_POS =      2;
    private static final int SEA_POS =      3;
    private static final int SEAKS_POS =    4;
    private static final int MODE_POS =     5;
    private static final int PADDING_POS =  6;
    private static final int INTHASH_POS =  7;
    private static final int MAC_POS =      8;
    private static final int MAKKS_POS =    9;

    private static Pattern regexp = Pattern.compile(XML_REGEX);

    public static EndPoint getEndPoint(String fileName, String ipmc) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(fileName));
        String fileString = new String(encoded, StandardCharsets.UTF_8);

        Matcher m  = regexp.matcher(fileString);

        while(m.find()) {
            String ip = m.group(IP_PORT_POS);

            if(ip.equals(ipmc)) {
                EndPoint endPoint = new EndPoint(
                        ip,
                        m.group(SID_POS),
                        m.group(SEA_POS),
                        m.group(SEAKS_POS),
                        m.group(MODE_POS),
                        m.group(PADDING_POS),
                        m.group(INTHASH_POS),
                        m.group(MAC_POS),
                        m.group(MAKKS_POS)
                );
                return endPoint;
            }
        }
        throw new EndPointException();
    }

}