package org.tokenscript.attestation.core;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;

public class UNSignature implements UnpredictableNumberTool {
    private static final Logger logger = LogManager.getLogger(UNSignature.class);
    private final SecureRandom random;
    private final String domain;
    private final long validityInMs;
    private final AsymmetricKeyParameter publicKey;
    private final AsymmetricKeyParameter privateKey;

    public UNSignature(AsymmetricCipherKeyPair keys, String domain) {
        this(new SecureRandom(), keys, domain);
    }

    public UNSignature(AsymmetricKeyParameter publicKey, String domain) {
        this(new SecureRandom(), publicKey, domain);
    }

    public UNSignature(SecureRandom random, AsymmetricCipherKeyPair keys, String domain) {
        this(random, keys, domain, DEFAULT_VALIDITY_IN_MS);
    }

    public UNSignature(SecureRandom random, AsymmetricKeyParameter publicKey, String domain) {
        this(random, publicKey, domain, DEFAULT_VALIDITY_IN_MS);
    }

    public UNSignature(SecureRandom random, AsymmetricKeyParameter publicKey, String domain, long validityInMs) {
        this(random, new AsymmetricCipherKeyPair(publicKey, null), domain, validityInMs);
    }

    public UNSignature(SecureRandom random, AsymmetricCipherKeyPair keys, String domain, long validityInMs) {
        this.random = random;
        this.domain = domain.toLowerCase();
        this.validityInMs = validityInMs;
        this.publicKey = keys.getPublic();
        this.privateKey = keys.getPrivate();
        if (!Eip712Common.isDomainValid(domain)) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Domain is not a valid domain"));
        }
    }

    @Override
    public String getDomain() {
        return domain;
    }

    @Override
    public UnpredictableNumberBundle getUnpredictableNumberBundle() {
        return getUnpredictableNumberBundle(null);
    }

    @Override
    public UnpredictableNumberBundle getUnpredictableNumberBundle(byte[] context) {
        long expiration = Clock.systemUTC().millis() + validityInMs;
        byte[] randomness = random.generateSeed(BYTES_IN_SEED);
        return new UnpredictableNumberBundle(getUnpredictableNumber(randomness, expiration, context), randomness, domain, expiration, context);
    }

    private String getUnpredictableNumber(byte[] randomness, long expirationInMs, byte[] context) {
        byte[] rawUN = getRawUN(randomness, expirationInMs, context);
        byte[] sig = SignatureUtility.signWithEthereum(rawUN, privateKey);
        // Let the UN be the signature
        return URLUtility.encodeData(sig);
    }

    /**
     * Construct a byte array of the content to be used in constructing the UN.
     * Context is allowed to be null, in which case, it is not included.
     */
    private byte[] getRawUN(byte[] randomness, long expirationInMs, byte[] context) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(UnpredictableNumberTool.longToBytes(expirationInMs));
            outputStream.write(randomness, 0, BYTES_IN_SEED);
            if (context != null) {
                outputStream.write(UnpredictableNumberTool.hashContext(context), 0, BYTES_IN_SEED);
            }
            outputStream.write(domain.getBytes(StandardCharsets.UTF_8), 0, domain.getBytes(StandardCharsets.UTF_8).length);
            outputStream.close();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not create UN message", e);
        }
    }

    @Override
    public boolean validateUnpredictableNumber(String un, byte[] context, long expirationInMs) {
        return validateUnpredictableNumber(un, context, expirationInMs, null);
    }

    @Override
    public boolean validateUnpredictableNumber(String un, byte[] randomness, long expirationInMs, byte[] context) {
        if (Clock.systemUTC().millis() > expirationInMs) {
            logger.error("Unpredictable number has expired");
            return false;
        }
        byte[] rawUN = getRawUN(randomness, expirationInMs, context);
        if (!SignatureUtility.verifyEthereumSignature(rawUN, URLUtility.decodeData(un), publicKey)) {
            logger.error("The unpredictable number is computed incorrectly. Either wrong key or wrong domain");
            return false;
        }
        return true;
    }
}
