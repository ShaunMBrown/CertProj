
package certproj;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

public class CertUtil {

	public static CertDetails getCertDetails(String jksPath, String keyStoreType, String jksPassword) {

		CertDetails certDetails = null;

		try {

			boolean isAliasWithPrivateKey = false;
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			char[] password = (jksPassword != null) ? jksPassword.toCharArray() : null;
			// Provide location of Java Keystore and password for access
			keyStore.load(new FileInputStream(jksPath), password);
			// iterate over all aliases
			Enumeration<String> es = keyStore.aliases();
			String alias = "";
			while (es.hasMoreElements()) {
				alias = (String) es.nextElement();
				// if alias refers to a private key break at that point
				// as we want to use that certificate
				if (isAliasWithPrivateKey = keyStore.isKeyEntry(alias)) {
					break;
				}
			}

			if (isAliasWithPrivateKey) {

				KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
						new KeyStore.PasswordProtection(jksPassword.toCharArray()));

				PrivateKey myPrivateKey = pkEntry.getPrivateKey();

				// Load certificate chain
				Certificate[] chain = keyStore.getCertificateChain(alias);

				certDetails = new CertDetails();
				certDetails.setKey(myPrivateKey);
				certDetails.setX509Certificate((X509Certificate) chain[0]);

			}

		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			e.printStackTrace();
		}

		return certDetails;
	}

	public static CertDetails extractPublicCert(String fileName) throws Exception {
		CertDetails publicCertDetails = new CertDetails();
		FileInputStream fis = new FileInputStream(fileName);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Collection<? extends Certificate> c = cf.generateCertificates(fis);
		Iterator<? extends Certificate> i = c.iterator();
		if (i.hasNext()) {
			X509Certificate xCert = (X509Certificate) i.next();
			PublicKey pubKey = xCert.getPublicKey();
			publicCertDetails.setX509Certificate(xCert);
			publicCertDetails.setKey(pubKey);
		}

		return publicCertDetails;
	}

}
