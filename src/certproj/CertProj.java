package certproj;

import java.security.KeyStore;
import java.security.Key;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.crypto.*;
import java.io.File;
import java.util.Enumeration;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.util.Date;

public class CertProj {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //InputStream input = getClass().getResourceAsStream("Raghupri.pfx");
        //File directory = new File("./");
        //System.out.println(directory.getAbsolutePath());
        File resourceFile = new File("./Certs/Raghupri.pfx");
        //System.out.println(resourceFile.toString());
        //checkExpire();
        
        CertDetails certDetails = CertUtil.getCertDetails("./Certs/Raghupri.pfx", "raghu");
        System.out.println(certDetails.getPrivateKey().toString());
        
        // Prints Certificate:
        System.out.println(certDetails.getX509Certificate());
        
    }
    
    public static void openCert(String certName, String password) {
        
    }
    
    public static void checkExpire() {

        try {
            KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            char[] password= "raghu".toCharArray();

            keystore.load(new FileInputStream("./Certs/Raghupri.pfx"),password);
            //keystore.load(new FileInputStream("./Certs/Raghupub.cer"),password);
            //keystore.load(new FileInputStream(certificate), password);
            kmf.init(keystore, password);
            Enumeration<String> aliases = keystore.aliases();
            while(aliases.hasMoreElements()){
                String alias = aliases.nextElement();
                if(keystore.getCertificate(alias).getType().equals("X.509")){
                    Date expDate = ((X509Certificate) keystore.getCertificate(alias)).getNotAfter();
                    Date fromDate= ((X509Certificate) keystore.getCertificate(alias)).getNotBefore();
                    System.out.println("Expiray Date:-"+expDate );
                    System.out.println("From Date:-"+fromDate);
                    //System.out.println(((X509Certificate) keystore.getCertificate(alias)).toString());
                
                    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(alias,
                                    new KeyStore.PasswordProtection(password));

                    PrivateKey myPrivateKey = pkEntry.getPrivateKey();
                    System.out.println(myPrivateKey.toString());
                }
                
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
