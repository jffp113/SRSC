package SecureProtocol.SecureHandshake;

import SecureProtocol.SecureHandshake.Messages.Components.CertificateUtil;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.Key;
import java.security.cert.Certificate;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class Server {

    public static final int N_THREADS = 10;
    public static final int PORT = 6789;

    private ThreadPoolExecutor threadPool;

    private final ServerSocket serverSocket;

    public Server() throws IOException {
        threadPool = (ThreadPoolExecutor) Executors.newFixedThreadPool(N_THREADS);
        serverSocket = new ServerSocket(PORT);
    }

    public void startToServe() throws IOException {
        Key key = CertificateUtil.getPersonalPrivateKey();
        while(true){
            System.out.println("Waiting for client");
            threadPool.execute(new RequestHandler(serverSocket.accept()));
        }
    }

    public static void main(String[] args) throws IOException {
        (new Server()).startToServe();
    }

}
