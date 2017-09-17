/**
 * 
 */
package de.oderkerk.example.security.password;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Functionality to store a password securely and validate against it If you see
 * here SHA1 you could thinks thats bad , but in this context with BKDF2 sha1 is
 * ok
 * 
 * @author Odin
 * @since 17.09.2017
 *
 */
public class PasswordSecurity {
	/**
	 * Iterations used during hashing and securing
	 */
	private static final int INTERRATIONS = 1000;
	/**
	 * Used algorithm for hashing
	 */
	private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA512";
	/**
	 * Used algorithm for SecureRandom function
	 */
	private static final String SECURERANDOM_ALGORITHM = "SHA1PRNG";

	/**
	 * Logging
	 */
	private static Logger LOGGER = LoggerFactory.getLogger(PasswordSecurity.class);

	/**
	 * hidden contructor to disable instantiation of an object, because only static
	 * methods are provided in this class
	 */
	private PasswordSecurity() {
	}

	/**
	 * Creating a hash of the password
	 * 
	 * @param password
	 *            to be secured
	 * @return String with secured password and additional information for verifying
	 *         process
	 * @throws NoSuchAlgorithmException
	 *             thrown if the SecretKeyFactioy don't find the chosen algorithm
	 * @throws InvalidKeySpecException
	 *             the key specification is invalid
	 */
	public static String generateStrongPasswordHash(String password)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		/**
		 * Convert the password to a char array to further use
		 */
		char[] chars = password.toCharArray();
		/**
		 * generate the salt
		 */
		byte[] salt = getSalt();

		/**
		 * Generate the PBEKeySpec
		 */
		PBEKeySpec spec = new PBEKeySpec(chars, salt, INTERRATIONS, 64 * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
		byte[] hash = skf.generateSecret(spec).getEncoded();
		return INTERRATIONS + ":" + toHex(salt) + ":" + toHex(hash);
	}

	/**
	 * Validate the Password given , against the stores password
	 * 
	 * @param originalPassword
	 *            password which is entered by the user
	 * 
	 * @param storedPassword
	 *            password which is stored in DB or elsewhere
	 * 
	 * @return boolean is valid or not
	 * 
	 * @throws NoSuchAlgorithmException
	 *             thrown if the SecretKeyFactioy don't find the chosen algorithm
	 * @throws InvalidKeySpecException
	 *             the key specification is invalid
	 */
	public static boolean validatePassword(String originalPassword, String storedPassword)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		LOGGER.debug("Validate Password against the stored password");
		/**
		 * Splitting the stored password into iteration, salt and the hash of the
		 * password
		 */
		String[] parts = storedPassword.split(":");
		/**
		 * Used iterations during generating the strong password hash
		 */
		int iterations = Integer.parseInt(parts[0]);
		/**
		 * Used salt
		 */
		byte[] salt = fromHex(parts[1]);
		/**
		 * has of password
		 */
		byte[] hash = fromHex(parts[2]);

		// Hashing the entered password with the settings of the stored password

		PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
		byte[] testHash = skf.generateSecret(spec).getEncoded();

		int diff = hash.length ^ testHash.length;
		for (int i = 0; i < hash.length && i < testHash.length; i++) {
			diff |= hash[i] ^ testHash[i];
		}
		LOGGER.debug("Result of compare = " + diff);
		return diff == 0;
	}

	/**
	 * Generate a salt
	 * 
	 * @return byte[] of salt generated Salt
	 * @throws NoSuchAlgorithmException
	 *             thrown if the SecureRandom don't find the chosen algorithm
	 */
	private static byte[] getSalt() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance(SECURERANDOM_ALGORITHM);
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt;
	}

	/**
	 * Convert Byte[] to String
	 * 
	 * @param array
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static String toHex(byte[] array) throws NoSuchAlgorithmException {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0) {
			return String.format("%0" + paddingLength + "d", 0) + hex;
		} else {
			return hex;
		}
	}

	/**
	 * String to byte[]
	 * 
	 * @param hex
	 * @return byte[]
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] fromHex(String hex) throws NoSuchAlgorithmException {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}

}
