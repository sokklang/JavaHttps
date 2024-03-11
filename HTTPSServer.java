import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStore;

public class HTTPSServer {

    public static void main(String[] args) {
        try {
            // Load the keystore containing the server certificate
            char[] password = "password".toCharArray(); // Change to your keystore password
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("keystore.jks"), password); // Change to your keystore path

            // Create and initialize the SSLContext with the loaded keystore
            KeyManagerFactory keyManagerFactory = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, password);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            // Create HTTPS server
            HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress("localhost", 443), 0); // Change
                                                                                                      // to
                                                                                                      // your
                                                                                                      // local
                                                                                                      // IP
                                                                                                      // address
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));

            // Context for the root path
            httpsServer.createContext("/", exchange -> {
                String response = "Hello from HTTPS server!";
                exchange.sendResponseHeaders(200, response.getBytes().length);
                exchange.getResponseBody().write(response.getBytes());
                exchange.getResponseBody().close();
            });

            // Start the server
            httpsServer.start();
            System.out.println("Server started on port 8443.");
        } catch (IOException | java.security.GeneralSecurityException e) {
            e.printStackTrace();
        }
    }
}
