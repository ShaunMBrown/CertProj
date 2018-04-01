package certproj;

import java.security.Key;
import java.security.cert.X509Certificate;
 
/**
 * Holds key and certificate information from
 * a pks file or public key/certificate
 * @author shaun
 */
public class CertDetails {

    private Key key;

    private X509Certificate x509Certificate;


    public Key getKey() {
            return key;
    }

    public void setKey(Key key) {
            this.key = key;
    }

    public X509Certificate getX509Certificate() {
            return x509Certificate;
    }

    public void setX509Certificate(X509Certificate x509Certificate) {
            this.x509Certificate = x509Certificate;
    } 
    

}
