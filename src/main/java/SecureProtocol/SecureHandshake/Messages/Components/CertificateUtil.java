package SecureProtocol.SecureHandshake.Messages.Components;

import java.io.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class CertificateUtil {
    private static final String PERM_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----";

    public static Certificate certificatesFromFile(File pemCertsFile) throws FileNotFoundException, CertificateException {
        return parseCertificates(new BufferedInputStream(new FileInputStream(pemCertsFile)));
    }

    public static Certificate parseCertificates(InputStream pemStream) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(pemStream);
    }

    public static String getPermCertificateAsString(Certificate certificate) throws CertificateEncodingException {
        return String.format(PERM_CERTIFICATE,Base64.getEncoder().encodeToString(certificate.getEncoded()));
    }
}
