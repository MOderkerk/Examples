/**
 * 
 */
package de.oderkerk.example.security.encryption;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Functionality for encryption and decryption of Strings using the on
 * BouncyCastle
 * 
 * @author Odin
 * @since 17.09.2017
 *
 */
public class StringEnAndDecryption {
	private Logger LOGGER = LoggerFactory.getLogger(this.getClass());

	/**
	 * Used salt with default
	 */
	private String salt = ";zuczsioc22jb%&S";

	/**
	 * Used passphrase with default
	 */
	private String passphrase = "1L:DWn?fmlse$%§%FFHRWT$WEfm1";

	/**
	 * Used number of iterations
	 */
	private int iterations = 2000;

	/**
	 * Length of key
	 */
	private int keyLength = 128;

	/**
	 * Constructor for overriding the dafault values of salt , passphrase,
	 * iterations and keylength
	 * 
	 * @param salt
	 * @param passphrase
	 * @param iterations
	 * @param keyLength
	 */
	public StringEnAndDecryption(String salt, String passphrase, int iterations, int keyLength) {
		super();
		this.salt = salt;
		this.passphrase = passphrase;
		this.iterations = iterations;
		this.keyLength = keyLength;
	}

	/**
	 * Contructor without salt , passphrase, iterations and keylength.
	 * 
	 * if the variables are not changed the default will be used which will be
	 * unsecure, because the code can be decompiled. Please use the contructor with
	 * all fields or the setter methods to override the values
	 */
	public StringEnAndDecryption() {
		super();
	}

	/**
	 * Encrypt a String with the given data
	 * 
	 * @param cleanString
	 * @return
	 * @throws Throwable
	 */
	public byte[] encryptString(String cleanString) throws Throwable {
		LOGGER.debug("Encrypting : {} ", cleanString);
		byte[] ciphertext = null;
		try {
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
			ciphertext = encrypt(passphrase, cleanString);

		} catch (Exception ex) {
			LOGGER.error(ex.toString(), ex);
			throw ex;
		}

		return ciphertext;

	}

	/**
	 * Decrypt a byte[]
	 * 
	 * @param encryptedData
	 *            byte[]
	 * @return String with clean data
	 * @throws Throwable
	 */
	public String decryptString(byte[] encryptedData) throws Throwable {
		LOGGER.debug("Decrypt data {}", new String(encryptedData));
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		return decrypt(passphrase, encryptedData);
	}

	/**
	 * Encrypt String with the set passphrase
	 * 
	 * @param passphrase
	 *            to be used
	 * @param plaintext
	 *            text to be encrypted
	 * @return byte[] with encrypted data
	 * @throws Exception
	 */
	private byte[] encrypt(String passphrase, String plaintext) throws Exception {

		SecretKey key = generateKey(passphrase);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, key, generateIV(cipher));
		return cipher.doFinal(plaintext.getBytes());
	}

	/**
	 * Decrypte the Text with the set passphrase
	 * 
	 * @param passphrase
	 *            to be used for decryption
	 * @param ciphertext
	 *            byte[] encrytped text
	 * @return String of cleantext
	 * @throws Exception
	 */
	private String decrypt(String passphrase, byte[] ciphertext) throws Exception {
		SecretKey key = generateKey(passphrase);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, key, generateIV(cipher));
		return new String(cipher.doFinal(ciphertext));
	}

	/**
	 * Generate the secretkey with the set salt, iteration, keylength
	 * 
	 * @param passphrase
	 *            to be used to generate the Secret key
	 * @return SecretKey
	 * @throws Exception
	 */
	private SecretKey generateKey(String passphrase) throws Exception {
		PBEKeySpec keySpec = new PBEKeySpec(passphrase.toCharArray(), salt.getBytes(), iterations, keyLength);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC");
		return keyFactory.generateSecret(keySpec);
	}

	/**
	 * Generate the IV Parameter spec
	 * 
	 * @param cipher
	 * @return
	 * @throws Exception
	 */
	private IvParameterSpec generateIV(Cipher cipher) throws Exception {
		return new IvParameterSpec(salt.getBytes());
	}

	/**
	 * @param salt
	 *            the salt to set
	 */
	public void setSalt(String salt) {
		this.salt = salt;
	}

	/**
	 * @param passphrase
	 *            the passphrase to set
	 */
	public void setPassphrase(String passphrase) {
		this.passphrase = passphrase;
	}

	/**
	 * @param iterations
	 *            the iterations to set
	 */
	public void setIterations(int iterations) {
		this.iterations = iterations;
	}

	/**
	 * @param keyLength
	 *            the keyLength to set
	 */
	public void setKeyLength(int keyLength) {
		this.keyLength = keyLength;
	}

}
