package SecureProtocol.Security;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CertificateChain  extends Certificate {
    private static final String PERM_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n";
    public static final String CERT_KEY_CATRUSTEDCERT_JKS = "CA/catrustedcert.jks";

    private List<Certificate> certChain;
    private Set<X509Certificate> trustCertificastes;
    private KeyStore truststore;

    public CertificateChain(List<Certificate> certChain) throws KeyStoreException {
        super("CertificateChain");
        this.certChain = certChain;
        loadKeyStoreAndTrustCertificates();
    }

    public void loadKeyStoreAndTrustCertificates() throws KeyStoreException {
        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(new FileInputStream(CERT_KEY_CATRUSTEDCERT_JKS), "chageit".toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.truststore = keystore;
        trustCertificastes = new HashSet<>();
        trustCertificastes.add((X509Certificate) truststore.getCertificate("ca"));

    }

    public boolean verify(String userName){
        X509Certificate CARoot = (X509Certificate)certChain.get(0);
        X509Certificate personal = (X509Certificate)certChain.get(1);

        //Verify Chain Date Validity
        for(Certificate cert : certChain){
            try {
                ((X509Certificate)cert).checkValidity();
            } catch (CertificateExpiredException e) {
                return false;
            } catch (CertificateNotYetValidException e) {
                return false;
            }
        }

        //Verify if CA is Known
        if(!trustCertificastes.contains(CARoot))
            return false;

        //Verify if client CA was signed by CARoot
        try {
            personal.verify(CARoot.getPublicKey());
        } catch (Exception e) {
            return false;
        }

        if(!(personal.getSubjectDN().getName().equals("CN=Leaf") ||
                personal.getSubjectDN().getName().equals("CN="+userName)))
            return false;

        return true;
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        for(Certificate cert : certChain){
            try {
                dataStream.write(cert.getEncoded());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return byteStream.toByteArray();
    }

    public String serializaToPem() throws Exception{
        StringBuilder bd = new StringBuilder();

        for(Certificate cer : this.certChain){
            bd.append(String.format(PERM_CERTIFICATE, Base64.getEncoder().encodeToString(cer.getEncoded())));
        }
        return bd.toString();
    }

    @Override
    public void verify(PublicKey key){
        throw new NotImplementedException();
    }

    @Override
    public void verify(PublicKey key, String sigProvider) {
        throw new NotImplementedException();
    }

    @Override
    public String toString() {
        return certChain.get(0).toString()+certChain.get(1).toString();
    }

    @Override
    public PublicKey getPublicKey() {
        return this.certChain.get(1).getPublicKey();
    }

}
