package SecureProtocol.SecureHandshake;

import SecureProtocol.SecureHandshake.Messages.SAAHPRequest;
import SecureProtocol.SecureSocket.Handler;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class RequestHandler implements Runnable{

    private final DataInputStream in;
    private final DataOutputStream out;

    public RequestHandler(Socket socket) throws IOException {
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
    }

    public void run(){
        final SAAHPRequest clientRequest;
        try {
            clientRequest = SAAHPRequest.getRequestFromInputStream(in);

        } catch (Exception e) {
            //Generate a Internal Error Exception TODO
            e.printStackTrace();
        }
    }




}
