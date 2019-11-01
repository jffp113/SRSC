package SecureProtocol.SecureHandshake.ServerComponents;

import SecureProtocol.SecureHandshake.RequestHandler;
import SecureProtocol.SecureSocket.KeyManagement.KeyManager;
import SecureProtocol.Utils;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class Server {

    private static final int N_THREADS = 10;
    private static final int PORT = 6789;

    private ThreadPoolExecutor threadPool;

    private final ServerSocket serverSocket;

    private Server() throws IOException {
        threadPool = (ThreadPoolExecutor) Executors.newFixedThreadPool(N_THREADS);
        serverSocket = new ServerSocket(PORT);
    }

    private void startToServe() throws IOException {
        while(true) threadPool.execute(new RequestHandler(serverSocket.accept()));
    }

    public static void main(String[] args) throws Exception {
        KeyManager.getInstance();
        Utils.log("");
        Utils.log2("Server initialized: " + InetAddress.getLocalHost().getHostAddress() + ":" + PORT);
        Utils.log("");
        (new Server()).startToServe();
    }

}
