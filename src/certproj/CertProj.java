package certproj;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;

import javax.net.ssl.KeyManagerFactory;

public class CertProj {

	private static CertDetails privateCertDetails;
	private static CertDetails publicCertDetails;
	private static CertDetails tcCertDetails;

	private static final String messageStr = "Our names are Danielle and Shaun. We are enrolled in CSE 539.";

	public static void main(String[] args) throws Exception {
		// Load all files and extract details
		privateCertDetails = CertUtil.getCertDetails("./Certs/Raghupri.pfx", "JKS", "raghu");
		publicCertDetails = CertUtil.extractPublicCert("./Certs/Raghupub.cer");
		tcCertDetails = CertUtil.extractPublicCert("./Certs/Trustcenter.cer");

		// Print each step from assignment
		printCertificateVerification();

		printCertificate();
		
		printKeys();

		printSignature();

		printMessages();

	}

	private static void printCertificateVerification() throws Exception {
		System.out.println("======================================");
		System.out.println("===========Cert Verification==========");
		System.out.println("======================================\n");
		System.out.println("There doesn't seem to be anything here :(");
		Signature sig = Signature.getInstance(publicCertDetails.getX509Certificate().getSigAlgName());
		sig.initVerify(publicCertDetails.getX509Certificate());
		boolean verified = sig.verify(publicCertDetails.getX509Certificate().getSignature());
		System.out.println("Verified: " + verified);
		System.out.println("Signature: " + sig.toString());
		System.out.println();
	}

	public static void printCertificate() {
		System.out.println("======================================");
		System.out.println("===========Raghu's Certificate=========");
		System.out.println("======================================\n");

		System.out.println();
	}

	/**
	 * Prints Raghu's private and public keys from the pks and cer files
	 * Prints the public key of the Certification Authority
	 */
	public static void printKeys() {
		System.out.println("======================================");
		System.out.println("===========Raghu's Private Key========");
		System.out.println("======================================\n");
		System.out.println(new String(Base64.getEncoder().encode(privateCertDetails.getKey().getEncoded())));
		System.out.println("\n======================================");
		System.out.println("===========Raghu's Public Key=========");
		System.out.println("======================================\n");
		System.out.println(new String(Base64.getEncoder().encode(publicCertDetails.getKey().getEncoded())));
		System.out.println("\n======================================");
		System.out.println("=============CA Public Key=============");
		System.out.println("======================================\n");
		System.out.println(new String(Base64.getEncoder().encode(tcCertDetails.getKey().getEncoded())));
		System.out.println();
	}

	public static void printSignature() {
		System.out.println("======================================");
		System.out.println("========Signature - Raghu's Cert======");
		System.out.println("======================================\n");
		System.out.println(new String(Base64.getEncoder().encode(publicCertDetails.getX509Certificate().getSignature())));
		System.out.println();
	}

	/**
	 * Uses RSAUtil class to encrypt the hardcoded string using Raghu's private key
	 * and then decrypt back to the original string using Raghu's public key.
	 * 
	 * @throws Exception
	 */
	public static void printMessages() throws Exception {
		System.out.println("======================================");
		System.out.println("==========Encrypted Message===========");
		System.out.println("======================================\n");
		RSAUtil rsaEncrypt = new RSAUtil(privateCertDetails);
		byte[] encryptedText = rsaEncrypt.encrypt(messageStr);
		System.out.println(new String(Base64.getEncoder().encode(encryptedText)));
		System.out.println("\n======================================");
		System.out.println("============Decrypted Message=========");
		System.out.println("======================================\n");
		RSAUtil rsaDecrypt = new RSAUtil(publicCertDetails);
		String decryptedText = rsaDecrypt.decrypt(encryptedText);
		System.out.println(decryptedText);
		System.out.println();
	}

	public static void checkExpire() {

		try {
			KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
			KeyStore keystore = KeyStore.getInstance("PKCS12");
			char[] password = "raghu".toCharArray();

			keystore.load(new FileInputStream("./Certs/Raghupri.pfx"), password);
			// keystore.load(new FileInputStream("./Certs/Raghupub.cer"),password);
			// keystore.load(new FileInputStream(certificate), password);
			kmf.init(keystore, password);
			Enumeration<String> aliases = keystore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (keystore.getCertificate(alias).getType().equals("X.509")) {
					Date expDate = ((X509Certificate) keystore.getCertificate(alias)).getNotAfter();
					Date fromDate = ((X509Certificate) keystore.getCertificate(alias)).getNotBefore();
					System.out.println("Expiray Date:-" + expDate);
					System.out.println("From Date:-" + fromDate);
					// System.out.println(((X509Certificate)
					// keystore.getCertificate(alias)).toString());

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
