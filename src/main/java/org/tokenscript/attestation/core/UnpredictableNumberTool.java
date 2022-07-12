package org.tokenscript.attestation.core;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public interface UnpredictableNumberTool {
    long DEFAULT_VALIDITY_IN_MS = 3600L * 1000L;
    // The amount of bytes to use in the randomness and also the size of the hash digest
    int BYTES_IN_SEED = AttestationCrypto.BYTES_IN_DIGEST;

    static byte[] hashContext(byte[] unhashedContext) {
        // To emulate a random oracle we use HMAC, but with a static key unique for the given usage, i.e, the name of this class and its package
        HMac staticKeyMAC = new HMac(new SHA3Digest(BYTES_IN_SEED * 8));
        byte[] hashedContext = new byte[staticKeyMAC.getMacSize()];
        // To emulate a random oracle we use HMAC, but with a static key unique for the given usage, i.e, the name of this class and its package
        staticKeyMAC.init(new KeyParameter(UnpredictableNumberTool.class.getName().getBytes(StandardCharsets.UTF_8)));
        staticKeyMAC.update(unhashedContext, 0, unhashedContext.length);
        staticKeyMAC.doFinal(hashedContext, 0);
        return hashedContext;
    }

    static byte[] longToBytes(long x) {
        ByteBuffer longBuffer = ByteBuffer.allocate(Long.BYTES);
        longBuffer.putLong(0, x);
        return longBuffer.array();
    }

    String getDomain();

    UnpredictableNumberBundle getUnpredictableNumberBundle();

    UnpredictableNumberBundle getUnpredictableNumberBundle(byte[] context);

    boolean validateUnpredictableNumber(String un, byte[] randomness, long expirationInMs);

    boolean validateUnpredictableNumber(String un, byte[] randomness, long expirationInMs, byte[] context);
}
