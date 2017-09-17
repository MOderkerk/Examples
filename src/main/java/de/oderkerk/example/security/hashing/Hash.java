/**
 * 
 */
package de.oderkerk.example.security.hashing;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;

/**
 * Class for hashing of Strings and files
 * 
 * @author Odin
 * @since 17.09.2017
 *
 */
public class Hash {

	/**
	 * Hashes a String with the given algorithm.
	 * 
	 * @param hashAlgorithm
	 *            String of algorithm to be used for hashing
	 * @param stringToHash
	 *            String to be hashed
	 * @param encoding
	 *            Encoding to be used, if null UTF-8 will be used as default
	 * @return byte[] of hash
	 * @throws UnsupportedEncodingException
	 *             Wrong encoding given
	 * @throws NoSuchAlgorithmException
	 *             Hashalgorithm invalid
	 */
	public String hashString(String hashAlgorithm, String stringToHash, String encoding)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {
		if (encoding == null) {
			encoding = "UTF-8";
		}
		MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
		md.update(stringToHash.getBytes(encoding));
		return DatatypeConverter.printHexBinary(md.digest());
	}

	/**
	 * Hashes a String with the given algorithm.
	 * 
	 * @param hashAlgorithm
	 *            String of algorithm to be used for hashing
	 * @param stringToHash
	 *            String to be hashed
	 * @param encoding
	 *            Encoding to be used, if null UTF-8 will be used as default
	 * @param hashToBeVerified
	 *            hash to be checked against
	 * @return byte[] of hash
	 * @throws UnsupportedEncodingException
	 *             Wrong encoding given
	 * @throws NoSuchAlgorithmException
	 *             Hashalgorithm invalid
	 */
	public boolean hashStringAndVerify(String hashAlgorithm, String stringToHash, String encoding,
			String hashToBeVerified) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		String calculatedHash = hashString(hashAlgorithm, stringToHash, encoding);
		if (calculatedHash.compareTo(hashToBeVerified) == 0) {
			return true;
		}
		return false;

	}

	/**
	 * Create a hash
	 * 
	 * @param fileToHash
	 *            File
	 * @param hashAlgorithm
	 *            Algorithm to be used
	 * 
	 * @return String of hash
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public String hashFile(File fileToHash, String hashAlgorithm) throws NoSuchAlgorithmException, IOException {
		MessageDigest algorithm = MessageDigest.getInstance(hashAlgorithm);
		FileInputStream fis = new FileInputStream(fileToHash);
		BufferedInputStream bis = new BufferedInputStream(fis);
		DigestInputStream dis = new DigestInputStream(bis, algorithm);

		// Read all lines and update dis
		while (dis.read() != -1)
			;

		// get the hash value as byte array
		byte[] hash = algorithm.digest();
		// Close all Streams
		dis.close();
		bis.close();
		fis.close();
		return DatatypeConverter.printHexBinary(hash);

	}

	/**
	 * Create a hash
	 * 
	 * @param fileToHash
	 *            File
	 * @param hashAlgorithm
	 *            Algorithm to be used
	 * @param hashToBeVerified
	 *            hash to be checked against
	 * @return boolean if the hash is valid
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public boolean hashFileAndVerify(File fileToHash, String hashAlgorithm, String hashToBeVerified)
			throws NoSuchAlgorithmException, IOException {
		String calculatedHash = hashFile(fileToHash, hashAlgorithm);
		if (calculatedHash.compareTo(hashToBeVerified) == 0) {
			return true;
		}
		return false;

	}

}
