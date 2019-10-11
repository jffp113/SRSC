package SecureSocket.Security;

import SecureSocket.Handler;

public class AbstractSecurity {

    protected byte[] handleException(Handler handler){
        try {
            return handler.handle();
        } catch ( Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
