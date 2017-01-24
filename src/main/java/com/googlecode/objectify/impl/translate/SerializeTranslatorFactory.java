package com.googlecode.objectify.impl.translate;

import com.google.appengine.api.datastore.Blob;
import com.googlecode.objectify.ObjectifyFactory;
import com.googlecode.objectify.annotation.Serialize;
import com.googlecode.objectify.impl.Path;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.SortedMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;


/**
 * <p>Loader which can load any serialized thing from a Blob.</p>
 *
 * @author Jeff Schnitzer <jeff@infohazard.org>
 */
public class SerializeTranslatorFactory implements TranslatorFactory<Object, Blob>
{
	private static final Logger log = Logger.getLogger(SerializeTranslatorFactory.class.getName());


	/**
	 * wrapper class to wrap encrypted form of an arbitrary serialized value with meta-data needed for its decryption
	 * (except for the actual encryption key itself, of course)
	 *
	 */
	static final class EncryptedBlob implements Serializable {

		// one of standard Java cipher implementations: https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html

		// Q: use an enum for this??

		//TODO: this is somewhat coupled to key type; nothing about KeyStoreService requires that it gives AES keys, but this implemention choice assumes it
		// CBC (block cipher mode) and padding are NOT coupled to key, but if we did couple
		// them than we could rotate keys AND cipher methods with a load-and-save schema migration
		// see: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Common_modes
		public static final String DEFAULT_CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";

		public static final long serialVersionUID = 1L;

		// identifier for cipher used to encrypt this object, if any
		String cipher = DEFAULT_CIPHER_TRANSFORMATION;

		// identifier for encryption key used to encrypt this object, if any
		// (used to support key rotation; eg, during rotation, will have mix of data encrypted using different keys)
		String keyId = null;

		//initialization vector used by encryption alg
		byte[] iv;

		//encrypted value; possibly compressed
		byte[] encryptedValue;

		static EncryptedBlob of(String cipher, String keyId, byte[] initializationVector, byte[] encryptedValue) {
			EncryptedBlob blob = new EncryptedBlob();
			blob.cipher = cipher;
			blob.keyId = keyId;
			blob.iv = initializationVector;
			blob.encryptedValue = encryptedValue;
			return blob;
		}
	}

	@Override
	public Translator<Object, Blob> create(TypeKey<Object> tk, CreateContext ctx, Path path) {
		final Serialize serializeAnno = tk.getAnnotationAnywhere(Serialize.class);

		// We only work with @Serialize classes
		if (serializeAnno == null)
			return null;

		// we need to stash factory reference here, rather than EncryptionKeyStore, bc
		// entity may be registered before EncryptionKeyStore
		final ObjectifyFactory fact = ctx.getFactory();

		return new ValueTranslator<Object, Blob>(Blob.class) {
			@Override
			protected Object loadValue(Blob value, LoadContext ctx, Path path) throws SkipException {

				// Need to be careful here because we don't really know if the data was serialized or not.  Start
				// with whatever the annotation says, and if that doesn't work, try the other option.
				try {

					// Start with the annotation
					boolean unzip = serializeAnno.zip();

					ByteArrayInputStream bais;


					// data may or may not be encrypted; rely on inspecting the stored value, rather than the annotation
					if (serializeAnno.encrypt()) {
						bais = new ByteArrayInputStream(decrypt(value, ctx));
					} else {
						//can use it straight
						bais = new ByteArrayInputStream(value.getBytes());
					}

					try {
						return readObject(bais, unzip);
					} catch (IOException ex) {	// will be one of ZipException or StreamCorruptedException
						if (log.isLoggable(Level.INFO))
							log.log(Level.INFO, "Error trying to deserialize object using unzip=" + unzip + ", retrying with " + !unzip, ex);

						unzip = !unzip;
						return readObject(bais, unzip);	// this will pass the exception up
					}
				} catch (Exception ex) {
					path.throwIllegalState("Unable to deserialize " + value, ex);
					return null;	// never gets here
				}
			}


			@Override
			protected Blob saveValue(Object value, boolean index, SaveContext ctx, Path path) throws SkipException {
				try {
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					OutputStream out = baos;

					if (serializeAnno.zip()) {
						Deflater deflater = new Deflater(serializeAnno.compressionLevel());
						out = new DeflaterOutputStream(out, deflater);
					}

					ObjectOutputStream oos = new ObjectOutputStream(out);
					oos.writeObject(value);
					oos.close();

					byte[] bytes = baos.toByteArray();

					if (serializeAnno.encrypt()) {
						//attempt to encrypt
						bytes = encrypt(baos.toByteArray());
					}

					return new Blob(bytes);

				} catch (IOException ex) {
					path.throwIllegalState("Unable to serialize " + value, ex);
					return null;	// never gets here
				}
			}


			/**
			 * encrypt value
			 */
			private byte[] encrypt (byte[] input)  {
				SortedMap<String, SecretKeySpec> keyMap = this.getKeyMap();

				if (keyMap == null) {
					return input;
				} else {
					SecretKeySpec key = keyMap.get(keyMap.firstKey());

					//AES IV length must match key length
					byte[] ivBytes = new byte[key.getEncoded().length];

					SecureRandom secureRandom = new SecureRandom();
					secureRandom.nextBytes(ivBytes);
					IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

					try {
						Cipher cipher = Cipher.getInstance(EncryptedBlob.DEFAULT_CIPHER_TRANSFORMATION);
						cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

						byte[] encrypted = new byte[cipher.getOutputSize(input.length)];
						int enc_len = cipher.update(input, 0, input.length, encrypted, 0);
						cipher.doFinal(encrypted, enc_len);

						//write encrypted blob
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
						ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
						EncryptedBlob encryptedBlob = EncryptedBlob.of(EncryptedBlob.DEFAULT_CIPHER_TRANSFORMATION, keyMap.firstKey(), ivBytes, encrypted);
						objectOutputStream.writeObject(encryptedBlob);
						objectOutputStream.close();
						outputStream.close();

						return outputStream.toByteArray();
					} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | ShortBufferException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | IOException e) {
						log.log(Level.WARNING, "failed to encrypt", e);
						return input;
					}
				}
			}


			/** Try reading an object from the stream */
			private Object readObject(ByteArrayInputStream bais, boolean unzip) throws IOException, ClassNotFoundException {
				bais.reset();
				InputStream in = bais;

				if (unzip)
					in = new InflaterInputStream(in);

				ObjectInputStream ois = new ObjectInputStream(in);
				return ois.readObject();
			}

			private SortedMap<String, SecretKeySpec> getKeyMap() {
				if (fact.getEncryptionKeyStore() == null) {
					log.log(Level.WARNING, "No EncryptionKeyStore registered");
				} else {
					SortedMap<String, SecretKeySpec> keyMap = fact.getEncryptionKeyStore().getEncryptionKeys();
					if (keyMap.isEmpty()) {
						log.log(Level.WARNING, "EncryptionKeyStore did not provide any keys");
					} else {
						return keyMap;
					}
				}
				return null;
			}

			/**
			 * attempt to decrypt value
             */
			private byte[] decrypt (Blob value, LoadContext ctx)
					throws NoSuchFieldException, IllegalAccessException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException {

				SortedMap<String, SecretKeySpec> keyMap = getKeyMap();
				byte[] decrypted;
				if (keyMap == null) {
					log.log(Level.WARNING, "No keys to decrypt with");
					return value.getBytes();
				} else {

					ObjectInputStream rawByteStream = new ObjectInputStream(new ByteArrayInputStream(value.getBytes()));

					try {
						EncryptedBlob encrypted = (EncryptedBlob) rawByteStream.readObject();

						SecretKeySpec key = keyMap.get(encrypted.keyId);

						if (key == null) {
							//couldn't find key to use when decrypting this value;
							throw new RuntimeException("Failed to decrypt value bc no key registered for id: " + encrypted.keyId);
						}

						IvParameterSpec ivSpec = new IvParameterSpec(encrypted.iv);
						Cipher cipher = Cipher.getInstance(encrypted.cipher);
						cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

						decrypted = new byte[cipher.getOutputSize(value.getBytes().length)];

						int dec_len = cipher.update(encrypted.encryptedValue, 0, encrypted.encryptedValue.length, decrypted, 0);
						cipher.doFinal(decrypted, dec_len);
					} catch (ClassCastException e) {
						//assume it's NOT encrypted
						decrypted = value.getBytes();
					}
					return decrypted;
				}

			}

		};
	}
}
