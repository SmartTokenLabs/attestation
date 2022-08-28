package org.tokenscript.attestation.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public interface UnpredictableNumberTool {
    long DEFAULT_VALIDITY_IN_MS = 3600L * 1000L;
    // The amount of bytes to use in the randomness and also the size of the hash digest
    int BYTES_IN_SEED = AttestationCrypto.BYTES_IN_DIGEST;
    String STATIC_KEY_STRING = "UnpredictableNumberTool";

    /**
     * Helper method to hash context information. This is needed to always ensure that context information has the same length.
     */
    static byte[] hashContext(byte[] unhashedContext) {
        HMac staticKeyMAC = new HMac(new SHA3Digest(BYTES_IN_SEED * 8));
        byte[] hashedContext = new byte[staticKeyMAC.getMacSize()];
        // To emulate a random oracle we use HMAC, but with a static key unique for the given usage
        staticKeyMAC.init(new KeyParameter(STATIC_KEY_STRING.getBytes(StandardCharsets.UTF_8)));
        staticKeyMAC.update(unhashedContext, 0, unhashedContext.length);
        staticKeyMAC.doFinal(hashedContext, 0);
        return hashedContext;
    }

    /**
     * Convert a long to a byte array
     */
    static byte[] longToBytes(long x) {
        ByteBuffer longBuffer = ByteBuffer.allocate(Long.BYTES);
        longBuffer.putLong(0, x);
        return longBuffer.array();
    }

    /**
     * Return the domain that will be used for validation.
     */
    String getDomain();

    /**
     * Computes an URL friendly base 64 encoding of A UN based on (expirationInMs || randomness || domain).
     * ExpirationInMs is computed from current time plus DEFAULT_VALIDITY_IN_MS
     * Both context and  randomness will be used in generating the UN.
     */
    UnpredictableNumberBundle getUnpredictableNumberBundle();

    /**
     * Computes an URL friendly base 64 encoding of A UN based on (expirationInMs || randomness || context || domain).
     * ExpirationInMs is computed from current time plus DEFAULT_VALIDITY_IN_MS
     * Both context and  randomness will be used in generating the UN.
     */
    UnpredictableNumberBundle getUnpredictableNumberBundle(byte[] context);

    /**
     * Validate a UN constructed without context information.
     */
    boolean validateUnpredictableNumber(String un, byte[] randomness, long expirationInMs);

    /**
     * Validate a UN constructed with context information.
     */
    boolean validateUnpredictableNumber(String un, byte[] randomness, long expirationInMs, byte[] context);
}
