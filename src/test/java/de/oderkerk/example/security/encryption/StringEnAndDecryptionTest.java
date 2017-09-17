package de.oderkerk.example.security.encryption;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.oderkerk.example.security.encryption.StringEnAndDecryption;

public class StringEnAndDecryptionTest {

	private StringEnAndDecryption service;

	@Before
	public void setUp() throws Exception {
		service = new StringEnAndDecryption();
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testEncryptString() throws Exception {
		try {
			byte[] encryptedData = service.encryptString("Cleanpassword");
			assertNotNull(encryptedData);
			String decryptedData = service.decryptString(encryptedData);
			assertEquals("Cleanpassword", decryptedData);
		} catch (Throwable e) {
			fail(e.getMessage());
		}
	}

}
