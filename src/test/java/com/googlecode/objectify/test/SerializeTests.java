package com.googlecode.objectify.test;

import com.google.common.io.BaseEncoding;
import com.googlecode.objectify.annotation.Cache;
import com.googlecode.objectify.annotation.Entity;
import com.googlecode.objectify.annotation.Id;
import com.googlecode.objectify.annotation.Serialize;
import com.googlecode.objectify.encryption.EncryptionKeyStore;
import com.googlecode.objectify.test.util.TestBase;
import com.googlecode.objectify.test.util.TestObjectifyFactory;
import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;
import java.util.*;

import static com.googlecode.objectify.test.util.TestObjectifyService.fact;
import static com.googlecode.objectify.test.util.TestObjectifyService.ofy;

/**
 * Tests of the {@code @Serialize} annotation
 */
public class SerializeTests extends TestBase
{
	@Entity
	@Cache
	public static class HasSerialize
	{
		@Id public Long id;
		@Serialize public Map<Long, Long> numbers = new HashMap<>();
	}

	@Test
	public void testSimpleSerialize() throws Exception
	{
		fact().register(HasSerialize.class);

		HasSerialize hs = new HasSerialize();
		hs.numbers.put(1L, 2L);
		hs.numbers.put(3L, 4L);

		HasSerialize fetched = ofy().saveClearLoad(hs);
		assert fetched.numbers.equals(hs.numbers);
	}

	/** */
	public static class HasLongs {
		@Serialize long[] longs;
	}

	@Entity
	@Cache
	public static class EmbedSerialize {
		@Id public Long id;
		public HasLongs simple;
	}

	@Test
	public void testEmbedSerialize() throws Exception
	{
		fact().register(EmbedSerialize.class);

		EmbedSerialize es = new EmbedSerialize();
		es.simple = new HasLongs();
		es.simple.longs = new long[] { 1L, 2L, 3L };

		EmbedSerialize fetched = ofy().saveClearLoad(es);
		assert Arrays.equals(es.simple.longs, fetched.simple.longs);
	}

	@Entity(name="HasSerialize")
	@Cache
	public static class HasSerializeZip
	{
		@Id public Long id;
		@Serialize(zip=true) public Map<Long, Long> numbers = new HashMap<>();
	}

	@Test
	public void testSerializeZip() throws Exception
	{
		fact().register(HasSerializeZip.class);

		HasSerializeZip hs = new HasSerializeZip();
		hs.numbers.put(1L, 2L);
		hs.numbers.put(3L, 4L);

		HasSerializeZip fetched = ofy().saveClearLoad(hs);
		assert fetched.numbers.equals(hs.numbers);
	}

	@Test
	public void testSerializeZipButReadUnzip() throws Exception
	{
		fact().register(HasSerializeZip.class);

		HasSerializeZip hs = new HasSerializeZip();
		hs.numbers.put(1L, 2L);
		hs.numbers.put(3L, 4L);

		ofy().save().entity(hs).now();

		// Now we need to read it using the non-zip annotation
		TestObjectifyFactory fact2 = new TestObjectifyFactory();
		fact2.register(HasSerialize.class);

		HasSerialize fetched = fact2.begin().load().type(HasSerialize.class).id(hs.id).now();
		assert fetched.numbers.equals(hs.numbers);
	}

	@Test
	public void testSerializeUnzipButReadZip() throws Exception
	{
		fact().register(HasSerialize.class);

		HasSerialize hs = new HasSerialize();
		hs.numbers.put(1L, 2L);
		hs.numbers.put(3L, 4L);

		ofy().save().entity(hs).now();

		// Now we need to read it using the zip annotation
		TestObjectifyFactory fact2 = new TestObjectifyFactory();
		fact2.register(HasSerializeZip.class);

		HasSerializeZip fetched = fact2.begin().load().type(HasSerializeZip.class).id(hs.id).now();
		assert fetched.numbers.equals(hs.numbers);
	}

	/**
	 * Serialize with Encryption tests
	 */
	public static EncryptionKeyStore mockKeyStore() {

		//NOTE: java default env settings prohibit keys >128 bits
		final byte[] AES_128_KEY = BaseEncoding.base64().decode("05B384DDDBD99FF6A0B100");

		return new EncryptionKeyStore() {
			@Override
			public SortedMap<String, SecretKeySpec> getEncryptionKeys() {
				SortedMap<String, SecretKeySpec> map = new TreeMap<>();
				map.put("key1", new SecretKeySpec(AES_128_KEY, "AES"));
				return map;
			}
		};
	}

	@Entity(name="HasSerialize")
	@Cache
	public static class HasSerializeEncrypt
	{
		@Id public Long id;
		@Serialize(encrypt=true) public Map<Long, Long> numbers = new HashMap<>();
	}

	@Test
	public void testSerializeAndEncrypt() {
		fact().setEncryptionKeyStore(mockKeyStore());
		fact().register(HasSerializeEncrypt.class);

		HasSerializeEncrypt hs = new HasSerializeEncrypt();
		hs.numbers.put(1L, 2L);
		hs.numbers.put(3L, 4L);

		ofy().save().entity(hs).now();

		TestObjectifyFactory fact2 = new TestObjectifyFactory();
		fact2.setEncryptionKeyStore(mockKeyStore());
		fact2.register(HasSerializeEncrypt.class);

		HasSerializeEncrypt fetched = fact2.begin().load().type(HasSerializeEncrypt.class).id(hs.id).now();
		assert fetched.numbers.equals(hs.numbers);
	}

	@Test
	public void testDeserializeLegacyUnencrypted() {
		fact().register(HasSerialize.class);

		HasSerialize hs = new HasSerialize();
		hs.numbers.put(1L, 2L);
		hs.numbers.put(3L, 4L);

		ofy().save().entity(hs).now();

		TestObjectifyFactory fact2 = new TestObjectifyFactory();
		fact2.setEncryptionKeyStore(mockKeyStore());
		fact2.register(HasSerializeEncrypt.class);

		HasSerializeEncrypt fetched = fact2.begin().load().type(HasSerializeEncrypt.class).id(hs.id).now();
		assert fetched.numbers.equals(hs.numbers);
	}

}
