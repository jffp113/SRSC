package SecureSocket.misc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class XMLSecurityProperty {

    public static final String XML_REGEX = "<(.*)>\\s*\\n*<SID>(.*)<\\/SID>\\s*\\n*" +
            "<SEA>(.*)<\\/SEA>\\s*\\n*<SEAKS>(.*)<\\/SEAKS>\\s*" +
            "\\n*<MODE>(.*)<\\/MODE>\\s*\\n*<PADDING>(.*)" +
            "<\\/PADDING>\\s*\\n*<INTHASH>(.*)<\\/INTHASH>\\s*\\n*<MAC>(.*)<\\/MAC>\\s*" +
            "\\n*<MAKKS>(.*)<\\/MAKKS>\\s*\\n*<\\/.*>\\s*\\n*";

    private static final int GROUP_ID_POS = 1;
    private static final int SID_POS =      2;
    private static final int SEA_POS =      3;
    private static final int SEAKS_POS =    4;
    private static final int MODE_POS =     5;
    private static final int PADDING_POS =  6;
    private static final int INTHASH_POS =  7;
    private static final int MAC_POS =      8;
    private static final int MAKKS_POS =    9;

    public static final String GROUP_ID =   "GROUP_ID";
    public static final String SID =        "SID";
    public static final String SEA =        "SEA";
    public static final String SEAKS =      "SEAKS";
    public static final String MODE =       "MODE";
    public static final String PADDING =    "PADDING";
    public static final String INTHASH =    "INTHASH";
    public static final String MAC =        "MAC";
    public static final String MAKKS =      "MAKKS";

    private static Pattern regexp = Pattern.compile(XML_REGEX);

    private List<EndPoint> propMap = new LinkedList<>();

    public XMLSecurityProperty(String fileName) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(fileName));
        String fileString = new String(encoded, StandardCharsets.UTF_8);

        Matcher m  = regexp.matcher(fileString);

        while(m.find()) {
            String id = m.group(GROUP_ID_POS);
            EndPoint endPoint = new EndPoint(
                    id,
                    m.group(SID_POS),
                    m.group(SEA_POS),
                    m.group(SEAKS_POS),
                    m.group(MODE_POS),
                    m.group(PADDING_POS),
                    m.group(INTHASH_POS),
                    m.group(MAC_POS),
                    m.group(MAKKS_POS)
            );
            propMap.add(endPoint);
        }
    }

    public List<EndPoint> getEndPoints() throws IOException {
        return this.propMap;
    }

}
