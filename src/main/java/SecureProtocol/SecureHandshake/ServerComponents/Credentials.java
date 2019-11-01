package SecureProtocol.SecureHandshake.ServerComponents;

import SecureProtocol.SecureHandshake.Exception.NotAuthorizedException;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class Credentials {
    private static Map<String,String> users ;

    static {
        File f = new File("users.db");
        users = new HashMap<>();
        try {
            DataInputStream in = new DataInputStream(new FileInputStream(f));
            BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
            String line;
            while((line = reader.readLine()) != null){
                String[] split = line.split("\\|");
                users.put(split[0],split[1]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static String getUserCredencial(String userName) throws NotAuthorizedException {
        String password = users.get(userName);
        if(password == null)
            throw new NotAuthorizedException("User does not exist: " + userName);
        return password;
    }
}
