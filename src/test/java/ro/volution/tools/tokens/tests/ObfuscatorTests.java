
package ro.volution.tools.tokens.tests;


import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;

import com.google.common.collect.ImmutableBiMap;
import com.google.common.io.BaseEncoding;

import ro.volution.tools.tokens.Obfuscator;
import ro.volution.tools.tokens.Obfuscator.Algorithms;
import ro.volution.tools.tokens.Obfuscator.Identifier32Token;


public final class ObfuscatorTests
			extends Object
{
	@Test
	public final void testAlgorithmsCiphers () {
		this.testAlgorithmsCiphers (false, false);
		this.testAlgorithmsCiphers (false, true);
		this.testAlgorithmsCiphers (true, false);
		this.testAlgorithmsCiphers (true, true);
	}
	
	@Test
	public final void testIdentifier32Coding () {
		final Obfuscator obfuscator = ObfuscatorTests.obfuscator1;
		this.testIdentifier32Coding (obfuscator, 0);
		for (int repeat = 0; repeat < ObfuscatorTests.repeats; repeat += 1)
			this.testIdentifier32Coding (obfuscator, ObfuscatorTests.random.nextInt ());
	}
	
	@Test
	public final void testIdentifier32DecodingVectors () {
		ObfuscatorTests.testIdentifier32DecodingVectors (ObfuscatorTests.obfuscator1, ObfuscatorTests.identifier32CodingTestVectors1);
		ObfuscatorTests.testIdentifier32DecodingVectors (ObfuscatorTests.obfuscator2, ObfuscatorTests.identifier32CodingTestVectors2);
	}
	
	@Test
	public final void testIdentifier32EncodingVectors () {
		ObfuscatorTests.testIdentifier32EncodingVectors (ObfuscatorTests.obfuscator1, ObfuscatorTests.identifier32CodingTestVectors1);
		ObfuscatorTests.testIdentifier32EncodingVectors (ObfuscatorTests.obfuscator2, ObfuscatorTests.identifier32CodingTestVectors2);
	}
	
	@Test
	public final void testIdentifier32TokenChecksum () {
		final Identifier32Token token = Identifier32Token.create (0, 0, 0);
		Assert.assertEquals (2077607535, token.checksum);
	}
	
	@Test
	public final void testObfuscatorCreation () {
		Obfuscator.create ();
	}
	
	@Test
	public final void testObfuscatorResolution () {
		final Obfuscator obfuscator = Obfuscator.create ();
		Assert.assertSame (obfuscator, Obfuscator.resolve (obfuscator.identity));
	}
	
	@Test
	public final void testRawChecksum () {
		final CRC32 crc32 = new CRC32 ();
		for (int index = 0; index < 12; index += 1)
			crc32.update (0);
		final int checksum = (int) crc32.getValue ();
		Assert.assertEquals (2077607535, checksum);
	}
	
	@Test
	public final void testRawCiphers () {
		this.testRawCiphers (false, false);
		this.testRawCiphers (false, true);
		this.testRawCiphers (true, false);
		this.testRawCiphers (true, true);
	}
	
	protected final void testAlgorithmsCiphers (final boolean randomKey, final boolean randomData) {
		final Algorithms algorithms = Algorithms.create ();
		final SecretKey key;
		if (randomKey)
			key = algorithms.generateCipherKey ();
		else
			key = algorithms.generateCipherKeyForTestingOnly (0);
		final Cipher encrypter = algorithms.createEncryptionCipher (key);
		final Cipher decrypter = algorithms.createDecryptionCipher (key);
		if (!randomKey)
			this.testCiphersCompliance (encrypter, decrypter);
		if (randomData)
			this.testCiphersRandomly (encrypter, decrypter, ObfuscatorTests.repeats);
	}
	
	protected final void testCipher (final Cipher cipher, final byte[] input, final byte[] expected) {
		final byte[] output = new byte[expected.length];
		try {
			cipher.doFinal (input, 0, input.length, output, 0);
		} catch (final GeneralSecurityException error) {
			throw (new Error (error));
		}
		Assert.assertArrayEquals (expected, output);
	}
	
	protected final void testCipher (final Cipher cipher, final String input, final String expected) {
		final byte[] inputBytes = BaseEncoding.base16 ().lowerCase ().decode (input);
		final byte[] expectedBytes = BaseEncoding.base16 ().lowerCase ().decode (expected);
		this.testCipher (cipher, inputBytes, expectedBytes);
	}
	
	protected final void testCiphers (final Cipher encrypter, final Cipher decrypter, final String plainText, final String cipherText) {
		this.testCipher (encrypter, plainText, cipherText);
		this.testCipher (decrypter, cipherText, plainText);
	}
	
	protected final void testCiphersCompliance (final Cipher encrypter, final Cipher decrypter) {
		/* NOTE: Simple test vectors. */
		this.testCiphers (encrypter, decrypter, "00000000000000000000000000000000", "66e94bd4ef8a2c3b884cfa59ca342b2e");
		this.testCiphers (encrypter, decrypter, "66e94bd4ef8a2c3b884cfa59ca342b2e", "f795bd4a52e29ed713d313fa20e98dbc");
		this.testCiphers (encrypter, decrypter, "f795bd4a52e29ed713d313fa20e98dbc", "a10cf66d0fddf3405370b4bf8df5bfb3");
		this.testCiphers (encrypter, decrypter, "a10cf66d0fddf3405370b4bf8df5bfb3", "47c78395e0d8ae2194da0a90abc9888a");
		/* NOTE: NIST test vectors from `ecb_vt.txt` from `http://csrc.nist.gov/archive/aes/rijndael/wsdindex.html`. */
		for (final Map.Entry<String, String> testVector : ObfuscatorTests.aes128NistZeroKeyTestVectors.entrySet ())
			this.testCiphers (encrypter, decrypter, testVector.getKey (), testVector.getValue ());
	}
	
	protected final void testCiphersRandomly (final Cipher encrypter, final Cipher decrypter, final int repeats) {
		for (int repeat = 0; repeat < repeats; repeat += 1) {
			final byte[] buffer0 = ObfuscatorTests.generateData (16);
			final byte[] buffer1 = new byte[16];
			final byte[] buffer2 = new byte[16];
			try {
				encrypter.doFinal (buffer0, 0, buffer0.length, buffer1, 0);
				decrypter.doFinal (buffer1, 0, buffer1.length, buffer2, 0);
			} catch (final GeneralSecurityException error) {
				throw (new Error (error));
			}
			Assert.assertArrayEquals (buffer0, buffer2);
		}
	}
	
	protected final void testIdentifier32Coding (final Obfuscator obfuscator, final int identifier) {
		final String token = obfuscator.encodeIdentifier32 (0, identifier);
		final int outcome = obfuscator.decodeIdentifier32 (0, token);
		Assert.assertEquals (identifier, outcome);
	}
	
	protected final void testRawCiphers (final boolean randomKey, final boolean randomData) {
		final Cipher encrypter;
		final Cipher decrypter;
		try {
			final SecretKey key;
			if (randomKey)
				key = KeyGenerator.getInstance ("AES").generateKey ();
			else {
				final byte[] keyBuffer = new byte[16];
				key = SecretKeyFactory.getInstance ("AES").generateSecret (new SecretKeySpec (keyBuffer, "AES"));
			}
			encrypter = Cipher.getInstance ("AES/ECB/NoPadding");
			decrypter = Cipher.getInstance ("AES/ECB/NoPadding");
			encrypter.init (Cipher.ENCRYPT_MODE, key);
			decrypter.init (Cipher.DECRYPT_MODE, key);
		} catch (final GeneralSecurityException error) {
			throw (new Error (error));
		}
		if (!randomKey)
			this.testCiphersCompliance (encrypter, decrypter);
		if (randomData)
			this.testCiphersRandomly (encrypter, decrypter, ObfuscatorTests.repeats);
	}
	
	protected static final byte[] generateData (final int size) {
		final byte[] data = new byte[size];
		ObfuscatorTests.random.nextBytes (data);
		return (data);
	}
	
	protected static final void testIdentifier32DecodingVectors (final Obfuscator obfuscator, final Map<Integer, String> testVectors) {
		for (final Map.Entry<Integer, String> testVector : testVectors.entrySet ()) {
			final String token = testVector.getValue ();
			final int expectedIdentifier = testVector.getKey ().intValue ();
			final int actualIdentifier = obfuscator.decodeIdentifier32 (0, token);
			Assert.assertEquals (expectedIdentifier, actualIdentifier);
		}
	}
	
	protected static final void testIdentifier32EncodingVectors (final Obfuscator obfuscator, final Map<Integer, String> testVectors) {
		for (final Map.Entry<Integer, String> testVector : testVectors.entrySet ()) {
			final int identifier = testVector.getKey ().intValue ();
			final String expectedToken = testVector.getValue ();
			final String actualToken = obfuscator.encodeIdentifier32 (0, identifier);
			Assert.assertEquals (expectedToken, actualToken);
		}
	}
	
	static {
		{
			final ImmutableBiMap.Builder<Integer, String> builder = new ImmutableBiMap.Builder<Integer, String> ();
			builder.put (Integer.valueOf (0), "70558d29cab8f27775f1e632de7e56fe");
			identifier32CodingTestVectors1 = builder.build ();
		}
		{
			final ImmutableBiMap.Builder<Integer, String> builder = new ImmutableBiMap.Builder<Integer, String> ();
			builder.put (Integer.valueOf (0), "5fc28b0e78d13f1ebe6626fc4cb1c015");
			identifier32CodingTestVectors2 = builder.build ();
		}
		{
			final ImmutableBiMap.Builder<String, String> builder = new ImmutableBiMap.Builder<String, String> ();
			builder.put ("80000000000000000000000000000000", "3ad78e726c1ec02b7ebfe92b23d9ec34");
			builder.put ("40000000000000000000000000000000", "45bc707d29e8204d88dfba2f0b0cad9b");
			builder.put ("20000000000000000000000000000000", "161556838018f52805cdbd6202002e3f");
			builder.put ("10000000000000000000000000000000", "f5569b3ab6a6d11efde1bf0a64c6854a");
			builder.put ("08000000000000000000000000000000", "64e82b50e501fbd7dd4116921159b83e");
			builder.put ("04000000000000000000000000000000", "baac12fb613a7de11450375c74034041");
			builder.put ("02000000000000000000000000000000", "bcf176a7eaad8085ebacea362462a281");
			builder.put ("01000000000000000000000000000000", "47711816e91d6ff059bbbf2bf58e0fd3");
			builder.put ("00800000000000000000000000000000", "b970dfbe40698af1638fe38bd3df3b2f");
			builder.put ("00400000000000000000000000000000", "f95b59a44f391e14cf20b74bdc32fcff");
			builder.put ("00200000000000000000000000000000", "720f74ae04a2a435b9a7256e49378f5b");
			builder.put ("00100000000000000000000000000000", "2a0445f61d36bfa7e277070730cf76da");
			builder.put ("00080000000000000000000000000000", "8d0536b997aefec1d94011bab6699a03");
			builder.put ("00040000000000000000000000000000", "674f002e19f6ed47eff319e51fad4498");
			builder.put ("00020000000000000000000000000000", "292c02c5cb9163c80ac0f6cf1dd8e92d");
			builder.put ("00010000000000000000000000000000", "fa321cf18ef5fe727dd82a5c1e945141");
			builder.put ("00008000000000000000000000000000", "a5a7afe1034c39cccebe3c584bc0be05");
			builder.put ("00004000000000000000000000000000", "4ff5a52e697e77d081205dbdb21cea39");
			builder.put ("00002000000000000000000000000000", "209e88dc94c9003000ce0769af7b7166");
			builder.put ("00001000000000000000000000000000", "5dee41af864cb4b650e5f51551824d38");
			builder.put ("00000800000000000000000000000000", "a79a63fa7e4503ae6d6e09f5f9053030");
			builder.put ("00000400000000000000000000000000", "a48316749fae7fac7002031a6afd8ba7");
			builder.put ("00000200000000000000000000000000", "d6eee8a7357a0e1d64262ca9c337ac42");
			builder.put ("00000100000000000000000000000000", "b013ca8a62a858053e9fb667ed39829e");
			builder.put ("00000080000000000000000000000000", "df6ea9e4538a45a52d5c1a43c88f4b55");
			builder.put ("00000040000000000000000000000000", "7d03ba451371591d3fd5547d9165c73b");
			builder.put ("00000020000000000000000000000000", "0e0426281a6277e186499d365d5f49ff");
			builder.put ("00000010000000000000000000000000", "dbc02169dd2059e6cc4c57c1fedf5ab4");
			builder.put ("00000008000000000000000000000000", "826590e05d167da6f00dcc75e22788eb");
			builder.put ("00000004000000000000000000000000", "34a73f21a04421d9786335faab49423a");
			builder.put ("00000002000000000000000000000000", "ed347d0e0128ee1a7392a1d36ab78aa9");
			builder.put ("00000001000000000000000000000000", "ee944b2fe6e9fc888042608da9615f75");
			builder.put ("00000000800000000000000000000000", "9e7c85a909ef7218ba7947cfb4718f46");
			builder.put ("00000000400000000000000000000000", "811ae07a0b2b1f816587fa73699ae77d");
			builder.put ("00000000200000000000000000000000", "68466fbf43c2fe13d4b18f7ec5ea745f");
			builder.put ("00000000100000000000000000000000", "d20b015c7191b219780956e6101f9354");
			builder.put ("00000000080000000000000000000000", "5939d5c1bbf54ee1b3e326d757bdde25");
			builder.put ("00000000040000000000000000000000", "b1fdafe9a0240e8ffea19ce94b5105d3");
			builder.put ("00000000020000000000000000000000", "d62962ece02cdd68c06bdfefb2f9495b");
			builder.put ("00000000010000000000000000000000", "b3bb2de6f3c26587ba8bac4f7ad9499a");
			builder.put ("00000000008000000000000000000000", "e0b1072d6d9ff703d6fbef77852b0a6b");
			builder.put ("00000000004000000000000000000000", "d8dd51c907f478de0228e83e61fd1758");
			builder.put ("00000000002000000000000000000000", "a42dffe6e7c1671c06a25236fdd10017");
			builder.put ("00000000001000000000000000000000", "25acf141550bfab9ef451b6c6a5b2163");
			builder.put ("00000000000800000000000000000000", "4da7fca3949b16e821dbc84f19581018");
			builder.put ("00000000000400000000000000000000", "7d49b6347cbcc8919c7fa96a37a7a215");
			builder.put ("00000000000200000000000000000000", "900024b29a08c6721b95ba3b753ddb4d");
			builder.put ("00000000000100000000000000000000", "6d2182fb283b6934d90ba7848cab5e66");
			builder.put ("00000000000080000000000000000000", "f73ef01b448d23a4d90de8b2f9666e7a");
			builder.put ("00000000000040000000000000000000", "4ad9cda2418643e9a3d926af5e6b0412");
			builder.put ("00000000000020000000000000000000", "7caec8e7e5953997d545b033201c8c5b");
			builder.put ("00000000000010000000000000000000", "3c43ca1f6b6864503e27b48d88230cf5");
			builder.put ("00000000000008000000000000000000", "44f779b93108fe9feec880d79ba74488");
			builder.put ("00000000000004000000000000000000", "9e50e8d9cfd3a682a78e527c9072a1cf");
			builder.put ("00000000000002000000000000000000", "68d000cbc838bbe3c505d6f814c01f28");
			builder.put ("00000000000001000000000000000000", "2cb2a9fec1acd1d9b0fa05205e304f57");
			builder.put ("00000000000000800000000000000000", "01eb2806606e46444520a5cc6180cd4b");
			builder.put ("00000000000000400000000000000000", "daa9b25168cc702326f217f1a0c0b162");
			builder.put ("00000000000000200000000000000000", "3e07e648975d9578d03555b1755807ed");
			builder.put ("00000000000000100000000000000000", "0b45f52e802c8b8de09579425b80b711");
			builder.put ("00000000000000080000000000000000", "659595da0b68f6df0dd6ca77202986e1");
			builder.put ("00000000000000040000000000000000", "05ff42873893536e58c8fa98a45c73c4");
			builder.put ("00000000000000020000000000000000", "b5b03421de8bbffc4eadec767339a9bd");
			builder.put ("00000000000000010000000000000000", "788bcd111ecf73d4e78d2e21bef55460");
			builder.put ("00000000000000008000000000000000", "909cd9ec6790359f982dc6f2393d5315");
			builder.put ("00000000000000004000000000000000", "332950f361535ff24efac8c76293f12c");
			builder.put ("00000000000000002000000000000000", "a68ccd4e330ffda9d576da436db53d75");
			builder.put ("00000000000000001000000000000000", "27c8a1ccfdb0b015d1ed5b3e77143791");
			builder.put ("00000000000000000800000000000000", "d76a4b95887a77df610dd3e1d3b20325");
			builder.put ("00000000000000000400000000000000", "c068ab0de71c66dae83c361ef4b2d989");
			builder.put ("00000000000000000200000000000000", "c2120bcd49eda9a288b3b4be79ac8158");
			builder.put ("00000000000000000100000000000000", "0c546f62bf2773cd0f564fceca7ba688");
			builder.put ("00000000000000000080000000000000", "18f3462bede4920213ccb66dab1640aa");
			builder.put ("00000000000000000040000000000000", "fe42f245edd0e24b216aebd8b392d690");
			builder.put ("00000000000000000020000000000000", "3d3eebc8d3d1558a194c2d00c337ff2b");
			builder.put ("00000000000000000010000000000000", "29aaedf043e785db42836f79be6cba28");
			builder.put ("00000000000000000008000000000000", "215f90c6744e2944358e78619159a611");
			builder.put ("00000000000000000004000000000000", "8606b1aa9e1d548e5442b06551e2c6dc");
			builder.put ("00000000000000000002000000000000", "987bb4b8740ec0ede7fea97df033b5b1");
			builder.put ("00000000000000000001000000000000", "c0a3500da5b0ae07d2f450930beedf1b");
			builder.put ("00000000000000000000800000000000", "525fdf8312fe8f32c781481a8daaae37");
			builder.put ("00000000000000000000400000000000", "bfd2c56ae5fb9c9de33a6944572a6487");
			builder.put ("00000000000000000000200000000000", "7975a57a425cdf5aa1fa929101f650b0");
			builder.put ("00000000000000000000100000000000", "bf174bc49609a8709b2cd8366daa79fe");
			builder.put ("00000000000000000000080000000000", "06c50c43222f56c874b1704e9f44bf7d");
			builder.put ("00000000000000000000040000000000", "0cec48cd34043ea29ca3b8ed5278721e");
			builder.put ("00000000000000000000020000000000", "9548ea34a1560197b304d0acb8a1698d");
			builder.put ("00000000000000000000010000000000", "22f9e9b1bd73b6b5b7d3062c986272f3");
			builder.put ("00000000000000000000008000000000", "fee8e934bd0873295059002230e298d4");
			builder.put ("00000000000000000000004000000000", "1b08e2e3eb820d139cb4abbdbe81d00d");
			builder.put ("00000000000000000000002000000000", "0021177681e4d90ceaf69dced0145125");
			builder.put ("00000000000000000000001000000000", "4a8e314452ca8a8a3619fc54bc423643");
			builder.put ("00000000000000000000000800000000", "65047474f7222c94c6965425ff1bfd0a");
			builder.put ("00000000000000000000000400000000", "e123f551a9c4a8489622b16f961a9aa4");
			builder.put ("00000000000000000000000200000000", "ef05530948b80915028bb2b6fe429380");
			builder.put ("00000000000000000000000100000000", "72535b7fe0f0f777cedcd55cd77e2ddf");
			builder.put ("00000000000000000000000080000000", "3423d8efc31fa2f4c365c77d8f3b5c63");
			builder.put ("00000000000000000000000040000000", "de0e51c264663f3c5dbc59580a98d8e4");
			builder.put ("00000000000000000000000020000000", "b2d9391166680947ab09264156719679");
			builder.put ("00000000000000000000000010000000", "10db79f23b06d263835c424af749adb7");
			builder.put ("00000000000000000000000008000000", "ddf72d27e6b01ec107ea3e005b59563b");
			builder.put ("00000000000000000000000004000000", "8266b57485a5954a4236751de07f6694");
			builder.put ("00000000000000000000000002000000", "669a501e1f1ade6e5523de01d6dbc987");
			builder.put ("00000000000000000000000001000000", "c20c48f2989725d461d1db589dc0896e");
			builder.put ("00000000000000000000000000800000", "de35158e7810ed1191825d2aa98fa97d");
			builder.put ("00000000000000000000000000400000", "4fe294f2c0f34d0671b693a237ebddc8");
			builder.put ("00000000000000000000000000200000", "087ae74b10ccbfdf6739feb9559c01a4");
			builder.put ("00000000000000000000000000100000", "5dc278970b7def77a5536c77ab59c207");
			builder.put ("00000000000000000000000000080000", "7607f078c77085184eaa9b060c1fbfff");
			builder.put ("00000000000000000000000000040000", "9db841531bcbe7998dad19993fb3cc00");
			builder.put ("00000000000000000000000000020000", "d6a089b654854a94560bae13298835b8");
			builder.put ("00000000000000000000000000010000", "e1e223c4cf90cc5d195b370d65114622");
			builder.put ("00000000000000000000000000008000", "1cbed73c50d053bdad372ceee54836a1");
			builder.put ("00000000000000000000000000004000", "d309e69376d257adf2bfda152b26555f");
			builder.put ("00000000000000000000000000002000", "740f7649117f0dee6eaa7789a9994c36");
			builder.put ("00000000000000000000000000001000", "76ae64417c297184d668c5fd908b3ce5");
			builder.put ("00000000000000000000000000000800", "6095fea4aa8035591f1787a819c48787");
			builder.put ("00000000000000000000000000000400", "d1ff4e7acd1c79967febab0f7465d450");
			builder.put ("00000000000000000000000000000200", "5f5ad3c42b9489557bb63bf49ecf5f8a");
			builder.put ("00000000000000000000000000000100", "fb56cc09b680b1d07c5a52149e29f07c");
			builder.put ("00000000000000000000000000000080", "ff49b8df4a97cbe03833e66197620dad");
			builder.put ("00000000000000000000000000000040", "5e070ade533d2e090ed0f5be13bc0983");
			builder.put ("00000000000000000000000000000020", "3ab4fb1d2b7ba376590a2c241d1f508d");
			builder.put ("00000000000000000000000000000010", "58b2431bc0bede02550f40238969ec78");
			builder.put ("00000000000000000000000000000008", "0253786e126504f0dab90c48a30321de");
			builder.put ("00000000000000000000000000000004", "200211214e7394da2089b6acd093abe0");
			builder.put ("00000000000000000000000000000002", "0388dace60b6a392f328c2b971b2fe78");
			builder.put ("00000000000000000000000000000001", "58e2fccefa7e3061367f1d57a4e7455a");
			aes128NistZeroKeyTestVectors = builder.build ();
		}
	}
	private static final ImmutableBiMap<String, String> aes128NistZeroKeyTestVectors;
	private static final ImmutableBiMap<Integer, String> identifier32CodingTestVectors1;
	private static final ImmutableBiMap<Integer, String> identifier32CodingTestVectors2;
	private static final Obfuscator obfuscator1 = Obfuscator.createForTestingOnly (1);
	private static final Obfuscator obfuscator2 = Obfuscator.createForTestingOnly (2);
	private static final SecureRandom random = new SecureRandom ();
	private static final int repeats = 0;
}
