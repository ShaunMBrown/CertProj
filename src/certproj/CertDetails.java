/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package certproj;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
 
/**
 *
 * @author shaun
 */
public class CertDetails {

    private PrivateKey privateKey;

    private X509Certificate x509Certificate;


    public PrivateKey getPrivateKey() {
            return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
    }

    public X509Certificate getX509Certificate() {
            return x509Certificate;
    }

    public void setX509Certificate(X509Certificate x509Certificate) {
            this.x509Certificate = x509Certificate;
    } 
}