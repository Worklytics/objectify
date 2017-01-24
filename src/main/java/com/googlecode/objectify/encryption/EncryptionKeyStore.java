package com.googlecode.objectify.encryption;

import javax.crypto.spec.SecretKeySpec;
import java.util.SortedMap;

/**
 * service through which to retrieve encryption keys
 *
 * @author Erik Schultink <erik@worklytics.co>
 */
public interface EncryptionKeyStore {

    /**
     * <p>sortedMap of encryption keys for keyId, in order of preference.
     *
     * on save, the first key will be used to encrypt data
     *
     * on load, Objectify will determine parse the hash of the key that data was encrypted with, and lookup the key's
     * value from the Map<> by this hash.</p>
     *
     *
     * build keys w something like new SecretKeySpec(plainKey.getBytes(), "AES");
     *
     * TODO: what if we want to rotate the Cipher approach?? should that be considered
     * part of the key identity too?
     *
     * @return
     */
    SortedMap<String, SecretKeySpec> getEncryptionKeys();
}
