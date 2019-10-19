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
    private static final File PERM_CERTIFICATE_FILE = new File("publickey.cer");
    private static final String PASSWORD = "Teste1";
    public static final String KEYSTORE = "keys.jks";

    private static Certificate personalCertificate;
    private static PrivateKey privateKey;

    static{
        personalCertificate = loadCertificate();
        privateKey = loadPersonalPrivateKey();
    }

    private static Certificate loadCertificate(){
        System.out.println("Load Certificate");
        try {
            return certificatesFromFile(PERM_CERTIFICATE_FILE);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PrivateKey loadPersonalPrivateKey(){
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(new FileInputStream(KEYSTORE), PASSWORD.toCharArray());
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

    public static String getPermCertificateString() throws Exception {
        return getPermCertificateAsString(personalCertificate);
    }
}
