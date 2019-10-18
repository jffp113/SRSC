package SecureProtocol.SecureHandshake.Messages.Components;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class CertificateUtil {
    private static final String PERM_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----";
    private static final File PERM_CERTIFICATE_FILE = new File("cert.perm");
    private static final String PASSWORD = "Teste";
    public static final String KEYSTORE = "privateKeystore.jks";

    private static Certificate personalCertificate = loadCertificate();
    private static PrivateKey privateKey = loadPersonalPrivateKey();

    private static Certificate loadCertificate(){
        try {
            return certificatesFromFile(PERM_CERTIFICATE_FILE);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PrivateKey loadPersonalPrivateKey(){
        FileInputStream is = null;
        try {
            is = new FileInputStream(KEYSTORE);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, PASSWORD.toCharArray());
            return (PrivateKey)keystore.getKey("myKey",PASSWORD.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Certificate certificatesFromFile(File pemCertsFile) throws FileNotFoundException, CertificateException {
        return parseCertificate(new BufferedInputStream(new FileInputStream(pemCertsFile)));
    }

    public static Certificate parseCertificate(InputStream pemStream) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(pemStream);
    }

    public static String getPermCertificateAsString(Certificate certificate) throws CertificateEncodingException {
        return String.format(PERM_CERTIFICATE,Base64.getEncoder().encodeToString(certificate.getEncoded()));
    }

    public static Certificate getPersonalCertificate(){
        return personalCertificate;
    }


    public static PrivateKey getPersonalPrivateKey(){
        return privateKey;
    }
}
