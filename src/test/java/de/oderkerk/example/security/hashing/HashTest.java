package de.oderkerk.example.security.hashing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import de.oderkerk.example.security.hashing.Hash;

public class HashTest {

	private Hash hash;
	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	@Before
	public void setUp() throws Exception {
		hash = new Hash();
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testHashString() throws Exception {
		String value = hash.hashString("MD5", "Testmessage", "UTF-8");
		assertEquals("9A68105303941D4A1F2326BA5608B846", value);
	}

	@Test
	public void testHashStringAndVerify() throws Exception {
		assertTrue(hash.hashStringAndVerify("MD5", "Testmessage", "UTF-8", "9A68105303941D4A1F2326BA5608B846"));
	}

	@Test
	public void testHashFile() throws Exception {
		String value = hash.hashFile(folder.newFile(), "SHA-512");
		assertEquals(
				"CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E",
				value);
	}

	@Test
	public void testHashFileAndVerify() throws Exception {
		assertTrue(hash.hashFileAndVerify(folder.newFile(), "SHA-512",
				"CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"));
	}

}
