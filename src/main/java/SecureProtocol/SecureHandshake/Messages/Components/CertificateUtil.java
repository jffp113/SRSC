package SecureProtocol.SecureHandshake.Messages.Components;

import SecureProtocol.Security.CertificateChain;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

public class CertificateUtil {
    private static final String PERM_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n";
    private static final File PERM_CERTIFICATE_FILE = new File("certchain.crt");
    private static final String PASSWORD = "password";
    public static final String KEYSTORE = "leaf.jks";

    private static Certificate personalCertificate;
    private static PrivateKey privateKey;

    static{
        personalCertificate = loadCertificate();
        privateKey = loadPersonalPrivateKey();
    }

    private static Certificate loadCertificate(){
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
            return (PrivateKey)keystore.getKey("leaf",PASSWORD.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Certificate certificatesFromFile(File pemCertsFile) throws Exception {
        return parseCertificates(new BufferedInputStream(new FileInputStream(pemCertsFile)));
    }

    public static Certificate parseCertificates(InputStream pemStream) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs = factory.generateCertificates(pemStream);
        Certificate[] toReturn = certs.toArray(new Certificate[] {});
        return new CertificateChain(Arrays.asList(toReturn));
    }


    public static String getPermCertificateAsString(Certificate certificate) throws Exception {
        if(certificate instanceof CertificateChain)
            return ((CertificateChain) certificate).serializaToPem();

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
