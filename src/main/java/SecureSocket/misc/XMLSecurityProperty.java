package SecureSocket.misc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class XMLSecurityProperty {

    public static final String XML_REGEX = "<(.*)>\\s*\\n*<SID>(.*)<\\/SID>\\s*\\n*" +
            "<SEA>(.*)<\\/SEA>\\s*\\n*<SEAKS>(.*)<\\/SEAKS>\\s*" +
            "\\n*<MODE>(.*)<\\/MODE>\\s*\\n*<P ADDING>(.*)" +
            "<\\/P ADDING>\\s*\\n*<INTHASH>(.*)<\\/INTHASH>\\s*\\n*<MAC>(.*)<\\/MAC>\\s*" +
            "\\n*<MAKKS>(.*)<\\/MAKKS>\\s*\\n*<\\/.*>\\s*\\n*";

    private static final int GROUP_ID_POS = 1;
    private static final int SID_POS = 2;
    private static final int SEA_POS = 3;
    private static final int SEAKS_POS = 4;
    private static final int MODE_POS = 5;
    private static final int PADDING_POS = 6;
    private static final int INTHASH_POS = 7;
    private static final int MAC_POS = 8;
    private static final int MAKKS_POS = 9;

    public static final String GROUP_ID = "GROUP_ID";
    public static final String SID = "SID";
    public static final String SEA = "SEA";
    public static final String SEAKS = "SEAKS";
    public static final String MODE = "MODE";
    public static final String PADDING = "PADDING";
    public static final String INTHASH = "INTHASH";
    public static final String MAC = "MAC";
    public static final String MAKKS = "MAKKS";

    private static Pattern r = Pattern.compile(XML_REGEX);
    public static List<Properties> getPropertiesFrom(String fileName) throws IOException {
        List<Properties> propList = new LinkedList<>();

        byte[] encoded = Files.readAllBytes(Paths.get(fileName));
        String fileString = new String(encoded, StandardCharsets.UTF_8);

        Matcher m  = r.matcher(fileString);

        while(m.find()) {
            Properties properties = new Properties();
            properties.put(GROUP_ID,m.group(GROUP_ID_POS));
            properties.put(SID,m.group(SID_POS));
            properties.put(SEA,m.group(SEA_POS));
            properties.put(SEAKS,m.group(SEAKS_POS));
            properties.put(MODE,m.group(MODE_POS));
            properties.put(PADDING,m.group(PADDING_POS));
            properties.put(INTHASH,m.group(INTHASH_POS));
            properties.put(MAC,m.group(MAC_POS));
            properties.put(MAKKS,m.group(MAKKS_POS));
            propList.add(properties);
        }

        return propList;
    }
}
