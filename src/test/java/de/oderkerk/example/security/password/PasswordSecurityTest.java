/**
 * 
 */
package de.oderkerk.example.security.password;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * PasswordSecurityTest
 * 
 * @author Odin
 * @since 17.09.2017
 *
 */
public class PasswordSecurityTest {

	String cleanPW = "Testpassword";
	String pwToVerifyAgainstCleanPW = "1000:d918866a3c22bca97d00d489c09e4ea9:99b8253ea8128e7d8a1fd2145697f17f4a1279e110469dba7664c8053c0d9f80945726b203b04ac090cd1498d40af49b332acc95edbfa5dcda91b52c9b836f47";

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for
	 * {@link de.oderkerk.example.security.password.PasswordSecurity#generateStrongPasswordHash(java.lang.String)}.
	 */
	@Test
	public void testGenerateStrongPasswordHash() throws Exception {
		try {
			String hashedPw = PasswordSecurity.generateStrongPasswordHash(cleanPW);
			assertNotNull(hashedPw);
			assertTrue(hashedPw.startsWith("1000"));
			assertEquals(3, hashedPw.split(":").length);
			System.out.println("Hashed information : " + hashedPw);

		} catch (Throwable ex) {
			fail(ex.toString());
		}
	}

	/**
	 * Test method for
	 * {@link de.oderkerk.example.security.password.PasswordSecurity#validatePassword(java.lang.String, java.lang.String)}.
	 */
	@Test
	public void testValidatePassword() throws Exception {
		assertTrue(PasswordSecurity.validatePassword(cleanPW, pwToVerifyAgainstCleanPW));
	}

}
