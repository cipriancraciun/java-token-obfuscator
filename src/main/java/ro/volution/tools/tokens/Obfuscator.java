
package ro.volution.tools.tokens;


import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.collect.MapMaker;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteArrayDataInput;
import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;


public final class Obfuscator
			extends Object
{
	protected Obfuscator () {
		this (0, null, false);
	}
	
	protected Obfuscator (final long identity, final SecretKey cipherKey, final boolean testing) {
		super ();
		/* NOTE: Initialize the algorithms. */
		this.algorithms = Algorithms.create ();
		this.testing = testing;
		/* NOTE: Generate an unique identity. */
		synchronized (Obfuscator.globalMonitor) {
			if (identity == 0)
				while (true) {
					final int trySession = this.algorithms.generateInteger ();
					if (trySession <= 0)
						continue;
					if (!Obfuscator.instances.containsKey (Integer.valueOf (trySession))) {
						this.identity = identity;
						break;
					}
				}
			else {
				if (Obfuscator.instances.containsKey (Long.valueOf (identity)))
					throw (new IllegalStateException ());
				this.identity = identity;
			}
			Obfuscator.instances.put (Long.valueOf (this.identity), this);
		}
		/* NOTE: Initialize cryptographic primitives. */
		if (cipherKey != null)
			this.cipherKey = cipherKey;
		else if (!this.testing)
			this.cipherKey = this.algorithms.generateCipherKey ();
		else
			this.cipherKey = this.algorithms.generateCipherKeyForTestingOnly (this.identity);
		this.encryptionCipher = this.algorithms.createEncryptionCipher (this.cipherKey);
		this.decryptionCipher = this.algorithms.createDecryptionCipher (this.cipherKey);
		/* NOTE: Initialize state. */
		if (!this.testing) {
			this.timestamp = System.currentTimeMillis ();
			this.counter = 0;
		} else {
			this.timestamp = 0;
			this.counter = 0;
		}
		this.localMonitor = new Object ();
	}
	
	public final int decodeIdentifier32 (final Class<?> type, final String token) {
		// FIXME: Assure uniqueness of type!
		return (this.decodeIdentifier32 (System.identityHashCode (type), token));
	}
	
	public final int decodeIdentifier32 (final int type, final String token) {
		final byte[] buffer = this.algorithms.decodeBuffer (token);
		this.decrypt (buffer);
		final Identifier32Token wrapper = Identifier32Token.decode (type, buffer);
		this.verifyTimestamp (wrapper.timestamp);
		return (wrapper.identifier);
	}
	
	public final String encodeIdentifier32 (final Class<?> type, final int identifier) {
		// FIXME: Assure uniqueness of type!
		return (this.encodeIdentifier32 (System.identityHashCode (type), identifier));
	}
	
	public final String encodeIdentifier32 (final int type, final int identifier) {
		final Identifier32Token wrapper = Identifier32Token.create (type, identifier);
		final byte[] buffer = Identifier32Token.encode (wrapper);
		this.encrypt (buffer);
		final String token = this.algorithms.encodeBuffer (buffer);
		return (token);
	}
	
	protected final void cipher (final Cipher cipher, final byte[] buffer) {
		if (buffer.length != this.algorithms.cipherBlockSize)
			throw (new ObfuscationError ());
		try {
			final int outputSize = cipher.doFinal (buffer, 0, buffer.length, buffer, 0);
			if (outputSize != this.algorithms.cipherBlockSize)
				throw (new ObfuscationError ());
		} catch (final GeneralSecurityException error) {
			throw (new ObfuscationError ());
		}
	}
	
	protected final void decrypt (final byte[] buffer) {
		synchronized (this.localMonitor) {
			this.cipher (this.decryptionCipher, buffer);
		}
	}
	
	protected final void encrypt (final byte[] buffer) {
		synchronized (this.localMonitor) {
			this.cipher (this.encryptionCipher, buffer);
		}
	}
	
	protected final long generateTimestamp () {
		// FIXME: Write the actual implementation!
		if (!this.testing) {
			this.timestamp = System.currentTimeMillis ();
			this.counter += 1;
		}
		return (this.timestamp);
	}
	
	protected final void verifyTimestamp (final long timestamp) {
		// FIXME: Write the actual implementation!
	}
	
	public final long identity;
	private final Algorithms algorithms;
	private final SecretKey cipherKey;
	private long counter;
	private final Cipher decryptionCipher;
	private final Cipher encryptionCipher;
	private final Object localMonitor;
	private final boolean testing;
	private long timestamp;
	
	public static final Obfuscator create () {
		return (new Obfuscator ());
	}
	
	@Deprecated
	public static final Obfuscator createForTestingOnly (final long identity) {
		return (new Obfuscator (identity, null, true));
	}
	
	public static final Obfuscator resolve (final long identity) {
		return (Obfuscator.instances.get (Long.valueOf (identity)));
	}
	
	static {
		instances = new MapMaker ().weakValues ().concurrencyLevel (16).makeMap ();
		globalMonitor = new Object ();
	}
	private static final Object globalMonitor;
	private static final ConcurrentMap<Long, Obfuscator> instances;
	
	public static final class Algorithms
				extends Object
	{
		private Algorithms () {
			super ();
			/* NOTE: Initialize cryptographic constants. */
			this.cipherKeyVariant = "AES";
			this.cipherVariant = "AES/ECB/NoPadding";
			this.cipherKeySize = 128 / 8;
			this.cipherBlockSize = 128 / 8;
			/* NOTE: Initialize cryptographic algorithms. */
			this.numberGenerator = new SecureRandom ();
			try {
				this.cipherKeyGenerator = KeyGenerator.getInstance (this.cipherKeyVariant);
				// NOTE:  See the note about Java 1.6 key generation compatibility.
				// this.cipherKeyFactory = SecretKeyFactory.getInstance (this.cipherKeyVariant);
			} catch (final GeneralSecurityException error) {
				throw (new RuntimeException (error));
			}
			/* NOTE: Initialize other algorithms. */
			this.bufferCoder = BaseEncoding.base16 ().lowerCase ();
		}
		
		public final Cipher createCipher (final SecretKey key, final int mode) {
			final Cipher cipher;
			try {
				cipher = Cipher.getInstance (this.cipherVariant);
			} catch (final GeneralSecurityException error) {
				throw (new RuntimeException (error));
			}
			try {
				cipher.init (mode, key, this.numberGenerator);
			} catch (final InvalidKeyException error) {
				throw (new RuntimeException (error));
			}
			return (cipher);
		}
		
		public final Cipher createDecryptionCipher (final SecretKey key) {
			return (this.createCipher (key, Cipher.DECRYPT_MODE));
		}
		
		public final Cipher createEncryptionCipher (final SecretKey key) {
			return (this.createCipher (key, Cipher.ENCRYPT_MODE));
		}
		
		public final byte[] decodeBuffer (final String buffer) {
			return (this.bufferCoder.decode (buffer));
		}
		
		public final String encodeBuffer (final byte[] buffer) {
			return (this.bufferCoder.encode (buffer));
		}
		
		public final SecretKey generateCipherKey () {
			return (this.cipherKeyGenerator.generateKey ());
		}
		
		@Deprecated
		public final SecretKey generateCipherKeyForTestingOnly (final long identity) {
			final SecretKeySpec keySpec;
			{
				final ByteArrayDataOutput keyStream = ByteStreams.newDataOutput (this.cipherKeySize);
				for (int index = 0; index < (this.cipherKeySize - 8); index += 1)
					keyStream.writeByte (0);
				keyStream.writeLong (identity);
				final byte[] keyBytes = keyStream.toByteArray ();
				keySpec = new SecretKeySpec (keyBytes, this.cipherKeyVariant);
			}
			return (keySpec);
			/* NOTE: The following seems not to work on Java 1.6.  However it seems to work without.
			final SecretKey key;
			try {
				key = this.cipherKeyFactory.generateSecret (keySpec);
			} catch (final GeneralSecurityException error) {
				throw (new RuntimeException (error));
			}
			return (key);
			*/
		}
		
		public final int generateInteger () {
			return (this.numberGenerator.nextInt ());
		}
		
		public final int cipherBlockSize;
		public final int cipherKeySize;
		public final String cipherKeyVariant;
		public final String cipherVariant;
		private final BaseEncoding bufferCoder;
		// NOTE:  See the note about Java 1.6 key generation compatibility.
		// private final SecretKeyFactory cipherKeyFactory;
		private final KeyGenerator cipherKeyGenerator;
		private final SecureRandom numberGenerator;
		
		public static final Algorithms create () {
			return (new Algorithms ());
		}
	}
	
	public static final class Identifier32Token
				extends Object
	{
		private Identifier32Token (final int type, final int identifier, final long timestamp) {
			super ();
			this.type = type;
			this.identifier = identifier;
			this.timestamp = timestamp;
			this.checksum = Identifier32Token.generateChecksum (this.type, this.identifier, this.timestamp);
		}
		
		public final int checksum;
		public final int identifier;
		public final long timestamp;
		public final int type;
		
		public static final Identifier32Token create (final int type, final int identifier) {
			return (Identifier32Token.create (type, identifier, 0));
		}
		
		public static final Identifier32Token create (final int type, final int identifier, final long timestamp) {
			return (new Identifier32Token (type, identifier, timestamp));
		}
		
		public static final Identifier32Token decode (final int type, final byte[] buffer) {
			// FIXME: Handle type information!
			if (buffer.length != (4 + 8 + 4))
				throw (new ObfuscationError ());
			final ByteArrayDataInput inputer = ByteStreams.newDataInput (buffer);
			final int identifier = inputer.readInt ();
			final long timestamp = inputer.readLong ();
			final int checksum = inputer.readInt ();
			final Identifier32Token token = Identifier32Token.create (type, identifier, timestamp);
			if (token.checksum != checksum)
				throw (new ObfuscationError ());
			return (token);
		}
		
		public static final byte[] encode (final Identifier32Token token) {
			// FIXME: Handle type information!
			final ByteArrayDataOutput outputer = ByteStreams.newDataOutput ();
			outputer.writeInt (token.identifier);
			outputer.writeLong (token.timestamp);
			outputer.writeInt (token.checksum);
			final byte[] buffer = outputer.toByteArray ();
			return (buffer);
		}
		
		protected final static int generateChecksum (final int type, final int identifier, final long timestamp) {
			// FIXME: Handle type information!
			final Hasher hasher = Identifier32Token.checksumGenerator.newHasher ();
			hasher.putInt (identifier);
			hasher.putLong (timestamp);
			return (hasher.hash ().asInt ());
		}
		
		private static final HashFunction checksumGenerator = Hashing.crc32 ();
	}
	
	public static final class ObfuscationError
				extends Error
	{
		private static final long serialVersionUID = 1L;
	}
}
