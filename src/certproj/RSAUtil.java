package certproj;

import java.security.Key;

import javax.crypto.Cipher;

/**
 * Uses the key provided to either encrypt or decrypt
 * the message provided. 
 * @author Danielle
 *
 */
public class RSAUtil {
	
	private Key key;
	private Cipher cipher;
	
	public RSAUtil(CertDetails certDetails) throws Exception {
		cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		key = certDetails.getKey();
	}
	
	/**
	 * Keep the byte[] returned from this method as-is to avoid
	 * any padding exceptions when decrypting!!
	 */
	public byte[] encrypt(String msg) throws Exception {
		cipher.init(Cipher.ENCRYPT_MODE, key);
		final byte[] cipherText = cipher.doFinal(msg.getBytes());
		return cipherText;
	}
	
	/**
	 * This should use the exact byte[] from the encrypt method in
	 * this class.
	 */
	public String decrypt(final byte[] encMsg) throws Exception {
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plainText = cipher.doFinal(encMsg);
		return new String(plainText);
	}
}
