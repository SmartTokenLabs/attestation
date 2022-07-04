package org.tokenscript.attestation.core;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Signature;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class SignatureUtility {
    private static final Logger logger = LogManager.getLogger(SignatureUtility.class);
    // OID for RSA PSS
    // See https://stackoverflow.com/questions/53728536/how-to-sign-with-rsassa-pss-in-java-correctly
    // for details on this and how to verify using openssl
    public static final AlgorithmIdentifier RSASSA_PSS_ALG = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.10"));
    // OID for RSA with SHA256
    public static final AlgorithmIdentifier RSA_PKCS1 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));
    // OID for a generic ECDSA public key
    public static final ASN1ObjectIdentifier OID_ECDSA_PUBLICKEY = new ASN1ObjectIdentifier("1.2.840.10045.2.1");
    // OID for a secp256k1 ECDSA key
    public static final ASN1ObjectIdentifier OID_SECP256K1_PUBLICKEY = new ASN1ObjectIdentifier("1.3.132.0.10");
    // Make sure that BC is always added as provider
    static final int providerIndex = Security.addProvider(new BouncyCastleProvider());
    public static final X9ECParameters SECP256K1 = SECNamedCurves.getByName("secp256k1");
    public static final ECDomainParameters SECP256K1_DOMAIN = new ECDomainParameters(SECP256K1.getCurve(), SECP256K1
            .getG(), SECP256K1.getN(), SECP256K1.getH());
    // We use the OID for generic ECDSA public key with specific parameters for secp256k1 instead of the OID for secp256k1, since decoding functions in libs won't understand that OID
    public static final AlgorithmIdentifier SECP256K1_IDENTIFIER = new AlgorithmIdentifier(
            OID_ECDSA_PUBLICKEY, SECP256K1);
    // AlgorithmIdentifier for ECDSA with recommend parameters
    public static final AlgorithmIdentifier ECDSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.2"));
    // Algorithm identifier for signature using ECDSA with SHA256
    public static final AlgorithmIdentifier ECDSA_WITH_SHA256 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));

    // Special Ethereum personal message Prefix
    private static final String personalMessagePrefix = "\u0019Ethereum Signed Message:\n";

    /*
     * One of the Ethereum design is, instead of verifying a message
     * against a known public key, a v value is included in the signature,
     * allowing an Ethereum address to be recovered from a message. The
     * advantage of this design is that message doesn't have to carry the
     * sender's Etheruem address, yet allowing a smart contract to check
     * the message against a dictionary of possible senders.

     * For example, Alice sends a cheque for Bob to redeem an ERC20
     * token. She doesn't need to include her Ethereum address as it can
     * be determined from the signature; the smart contract, instead of
     * verifying it against a large array of known users, can use the
     * recovered Ethereum address to look up the remaining balance.

     * This design is great however it breaks X9.62 key format:
     * ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }

     * In the scenario where the public key is known, a smart contract can
     * simply store the v value together with the public key; however, in
     * other situations, to avoid attempting v value 2 times, we can
     * selectively only use keys which result in a fixed v value. This
     * class replaced the constructECKeys() method just to do that.
     */
    public static AsymmetricCipherKeyPair constructECKeysWithSmallestY(SecureRandom rand) {
        AsymmetricCipherKeyPair keys;
        BigInteger yCoord;
        BigInteger fieldModulo = SECP256K1_DOMAIN.getCurve().getField()
                .getCharacteristic();
        // If the y coordinate is in the upper half of the field, then sample again until it to the lower half
        do {
            keys = constructECKeys(rand);
            ECPublicKeyParameters pk = (ECPublicKeyParameters) keys.getPublic();
            yCoord = pk.getQ().getAffineYCoord().toBigInteger();
        } while (yCoord.compareTo(fieldModulo.shiftRight(1)) > 0);
        return keys;
    }
    /**
     * Construct default keys; secp256k1
     * @param random
     */
    public static AsymmetricCipherKeyPair constructECKeys(SecureRandom random) {
        return constructECKeys(SECP256K1_DOMAIN, random);
    }

    public static AsymmetricCipherKeyPair constructECKeys(X9ECParameters ECDSACurve, SecureRandom random) {
        ECDomainParameters domain = new ECDomainParameters(ECDSACurve.getCurve(), ECDSACurve.getG(), ECDSACurve.getN(), ECDSACurve.getH());
        return constructECKeys(domain, random);
    }

    private static AsymmetricCipherKeyPair constructECKeys(ECDomainParameters domain, SecureRandom random) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(domain, random);
        generator.init(keygenParams);
        return generator.generateKeyPair();
    }

    /**
     * Extract the ECDSA SECP256K1 public key from its DER encoded BITString
     * @param input
     * @return
     */
    public static AsymmetricKeyParameter restoreDefaultKey(byte[] input) throws IOException {
        return restoreDefaultKey(SECP256K1_IDENTIFIER, input);
    }

    /**
     * Extract any public key from its DER encoded BITString and AlgorithmIdentifier
     * @param input
     * @return
     */
    public static AsymmetricKeyParameter restoreDefaultKey(AlgorithmIdentifier identifier, byte[] input) throws IOException {
        ASN1BitString keyEnc = DERBitString.getInstance(input);
        ASN1Sequence spkiEnc = new DERSequence(new ASN1Encodable[] {identifier, keyEnc});
        return restoreKeyFromSPKI(spkiEnc.getEncoded());
    }

    public static AsymmetricKeyParameter restoreKeyFromSPKI(byte[] input) throws IOException {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(input);
        return PublicKeyFactory.createKey(spki);
    }

    public static PrivateKey convertPrivateBouncyCastleKeyToJavaKey(AsymmetricKeyParameter bcKey) {
        try {
            KeyFactory ecKeyFac = getFactory(bcKey);
            byte[] encodedBCKey = PrivateKeyInfoFactory.createPrivateKeyInfo(bcKey).getEncoded();
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedBCKey);
            return ecKeyFac.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not convert key", e);
        }
    }

    public static PublicKey convertPublicBouncyCastleKeyToJavaKey(AsymmetricKeyParameter bcKey) {
        try {
            KeyFactory ecKeyFac = getFactory(bcKey);
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(bcKey);
            X509EncodedKeySpec encodedKey = new X509EncodedKeySpec(spki.getEncoded());
            return ecKeyFac.generatePublic(encodedKey);
        } catch (Exception e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not convert key", e);
        }
    }

    private static KeyFactory getFactory(AsymmetricKeyParameter key) throws Exception {
        if (key instanceof ECKeyParameters) {
            return KeyFactory.getInstance("EC", "BC");
        } else if (key instanceof RSAKeyParameters) {
            return KeyFactory.getInstance("RSA", "BC");
        } else {
            throw ExceptionUtil.throwException(logger,
                new IllegalArgumentException("Only ECDSA or RSA keys are supported"));
        }
    }

    public static KeyPair convertBouncyCastleKeysToJavaKey(AsymmetricCipherKeyPair bcKeys) {
        return new KeyPair(convertPublicBouncyCastleKeyToJavaKey(bcKeys.getPublic()), convertPrivateBouncyCastleKeyToJavaKey(
            bcKeys.getPrivate()));
    }

    /**
     * Code shamelessly stolen from https://medium.com/@fixone/ecc-for-ethereum-on-android-7e35dc6624c9
     * But then fixed due to a bug in that code.
     * @param key
     * @return
     */
    public static String addressFromKey(AsymmetricKeyParameter key) {
        ECPublicKeyParameters ecKey = (ECPublicKeyParameters) key;
        // Validate that the key is correct
        AttestationCrypto.validatePointToCurve(ecKey.getQ(), SECP256K1.getCurve());
        byte[] pubKey;
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
            pubKey = spki.getPublicKeyData().getOctets();
        } catch (IOException e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not create spki", e);
        }
        //discard the first byte which only tells what kind of key it is //i.e. encoded/un-encoded
        pubKey = Arrays.copyOfRange(pubKey,1,pubKey.length);
        byte[] hash = AttestationCrypto.hashWithKeccak(pubKey);
        //finally get only the last 20 bytes
        return "0x" + Hex.toHexString(Arrays.copyOfRange(hash,hash.length-20,hash.length)).toUpperCase();
    }

    public static byte[] signPersonalMsgWithEthereum(byte[] unsigned, AsymmetricKeyParameter signingKey) {
        return signPersonalMsgWithEthereum(unsigned, 0, signingKey);
    }

    public static byte[] signPersonalMsgWithEthereum(byte[] unsigned, int chainID, AsymmetricKeyParameter signingKey) {
        byte[] toSign = convertToPersonalEthMessage(unsigned);
        return signWithEthereum(toSign, chainID, signingKey);
    }

    public static byte[] signWithEthereum(byte[] unsigned, AsymmetricKeyParameter signingKey) {
        return signWithEthereum(unsigned, 0, signingKey);
    }

    public static byte[] signWithEthereum(byte[] unsigned, long chainID, AsymmetricKeyParameter signingKey) {
        byte[] digest = AttestationCrypto.hashWithKeccak(unsigned);
        BigInteger[] signature = computeInternalSignature(digest, (ECPrivateKeyParameters) signingKey);
        return normalizeAndEncodeEthereumSignature(signature, chainID);
    }

    /**
     * Constructs a DER encoded, non-malleable deterministic ECDSA signature using SHA 256
     * But still in accordance with EIP 2 (the y-coordinate is guaranteed to be less than n/2).
     * The deterministic approach used is the one from RFC 6979
     * @param toSign
     * @param key
     * @return
     */
    public static byte[] signDeterministicSHA256(byte[] toSign, AsymmetricKeyParameter key) {
        byte[] digest = AttestationCrypto.hashWithSHA256(toSign);
        BigInteger[] signature = computeInternalSignature(digest, (ECPrivateKeyParameters) key);
        return normalizeAndEncodeDerSignature(signature, ((ECKeyParameters) key).getParameters());
    }

    /**
     * Constructs a DER encoded indeterministic (randomized) ECDSA signature based on an already hashed value.
     * Despite being randomized this is done in accordance with EIP 2 (the y-coordinate is guaranteed to be less than n/2)
     * @param digest The digest to sign
     * @param key The key to use for signing.
     * @return
     */
    public static byte[] signHashedRandomized(byte[] digest, AsymmetricKeyParameter key) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, key);
        BigInteger[] signature = signer.generateSignature(digest);
        return normalizeAndEncodeDerSignature(signature, ((ECKeyParameters) key).getParameters());
    }

    private static byte[] normalizeAndEncodeDerSignature(BigInteger[] signature, ECDomainParameters params) {
        try {
            ASN1EncodableVector asn1 = new ASN1EncodableVector();
            asn1.add(new ASN1Integer(signature[0]));
            BigInteger s = normalizeS(signature[1], params);
            asn1.add(new ASN1Integer(s));
            return new DERSequence(asn1).getEncoded();
        } catch (Exception e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
        }
    }

    /**
     * Computes a signature on data that has already been hashed.
     * Specifically as a BigInteger array containing {r, s, v}, where v is the parity
     * of the y-coordinate of the curve point r is computed from.
     * @return The signature as {r, s, v} where v is the y-parity of R.
     */
    static BigInteger[] computeInternalSignature(byte[] digest, ECPrivateKeyParameters key) {
        BigInteger z = new BigInteger(1, digest);

        HMacDSAKCalculator randomnessProvider = new HMacDSAKCalculator(new KeccakDigest(256));
        randomnessProvider.init(key.getParameters().getN(), key.getD(), digest);
        BigInteger n = key.getParameters().getN();
        BigInteger r, k;
        ECPoint R;
        BigInteger baseS;
        do {
            do {
                k = randomnessProvider.nextK();
                R = key.getParameters().getG().multiply(k).normalize();
                r = R.getAffineXCoord().toBigInteger().mod(n);
            } while (r.equals(BigInteger.ZERO));
            baseS = k.modInverse(n).multiply(z.add(r.multiply(key.getD()))).mod(n);
        } while (baseS.equals(BigInteger.ZERO));
        BigInteger normalizedS = normalizeS(baseS, key.getParameters());
        // Validate R as a sanity check
        AttestationCrypto.validatePointToCurve(R, key.getParameters().getCurve());
        BigInteger v = R.getAffineYCoord().toBigInteger().mod(new BigInteger("2"));
        // Normalize parity in case s needs normalization, based on constant time, up to the underlying implementation
        BigInteger branch = !normalizedS.equals(baseS) ? BigInteger.ONE : BigInteger.ZERO;
        BigInteger normalizedV = (BigInteger.ONE.subtract(v)).multiply(branch).add((BigInteger.ONE.subtract(branch)).multiply(v));
        return new BigInteger[] {r, normalizedS, normalizedV};
    }

    static final String MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";
    static byte[] getEthereumMessagePrefix(int messageLength) {
        return MESSAGE_PREFIX.concat(String.valueOf(messageLength)).getBytes();
    }

    //code copied from Web3j:
    public static byte[] convertToPersonalEthMessage(byte[] msgToSign) {
        byte[] prefix = getEthereumMessagePrefix(msgToSign.length);
        byte[] result = new byte[prefix.length + msgToSign.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(msgToSign, 0, result, prefix.length, msgToSign.length);
        return result;
    }

    private static byte[] normalizeAndEncodeEthereumSignature(BigInteger[] signature, long chainID) {
        byte recoveryVal = computeRecoveryValue(signature[2], chainID);
        byte[] ethereumSignature = new byte[65];
        // This byte array can be up tp 33 bytes since it must contain a sign-bit
        // (which is always 0 in our case since we only work with positive numbers).
        // The byte array can also be less than 32 bytes if we are unlucky and have a really low r value
        byte[] r = signature[0].toByteArray();
        System.arraycopy(r, Math.max(0, r.length-32), ethereumSignature, Math.max(0, 32-r.length), Math.min(32, r.length));
        byte[] s = signature[1].toByteArray();
        System.arraycopy(s, Math.max(0, s.length-32), ethereumSignature, Math.max(32, 64-s.length), Math.min(32, s.length));
        ethereumSignature[64] = recoveryVal;
        return ethereumSignature;
    }

    /**
     * Computes the Ethereum recovery value using the parity of the y-coordinate of the R
     * that is the signature.
     * See https://bitcoin.stackexchange.com/questions/38351/ecdsa-v-r-s-what-is-v
     * @param v The y-coordinate parity of R
     * @param chainID Chain ID, 0, if before EIP155
     * @return 27 or 28 if chain ID = 0, otherwise value > 37
     */
    private static byte computeRecoveryValue(BigInteger v, long chainID) {
        // Compute parity of y
        byte recoveryValue = v.mod(new BigInteger("2")).byteValueExact();
        // If we are after the fork specified by EIP155 we must also take chain ID into account
        // See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
        if (chainID != 0) {
            recoveryValue += chainID * 2 + 35;
        } else {
            recoveryValue += 27;
        }
        return recoveryValue;
    }

    /**
     * Verify an Ethereum signature on a message that DOES NOT include the signed-by-Ethereum prefix when used outside of the blockchain
     */
    public static boolean verifyPersonalEthereumSignature(byte[] unsigned, byte[] signature, AsymmetricKeyParameter publicKey) {
        return verifyPersonalEthereumSignature(unsigned, signature, addressFromKey(publicKey), 0);
    }

    /**
     * Verify an Ethereum signature against an address on a message that DOES NOT include the signed-by-Ethereum prefix when used outside of the blockchain
     */
    public static boolean verifyPersonalEthereumSignature(byte[] unsignedWithoutPrefix, byte[] signature, String address, int chainId) {
        byte[] unsignedWithEthPrefix = convertToPersonalEthMessage(unsignedWithoutPrefix);
        return verifyEthereumSignature(unsignedWithEthPrefix, signature, address, chainId);
    }

    /**
     * Verify an Ethereum signature directly on @unsigned.
     */
    public static boolean verifyEthereumSignature(byte[] unsigned, byte[] signature, AsymmetricKeyParameter publicKey) {
        ECPoint Q = ((ECPublicKeyParameters) publicKey).getQ();
        AttestationCrypto.validatePointToCurve(Q, SECP256K1.getCurve());
        return verifyEthereumSignature(unsigned, signature, addressFromKey(publicKey), 0);
    }

    /**
     * VVerify an Ethereum signature directly on @unsigned.
     */
    public static boolean verifyEthereumSignature(byte[] unsigned, byte[] signature, String address, int chainId) {
        try {
            ECPublicKeyParameters publicKey = recoverEthPublicKeyFromSignature(
                unsigned, signature);
            if (!verifyKeyAgainstAddress(publicKey, address)) {
                logger.error("Address does not match key");
                return false;
            }
            if (getChainIdFromSignature(signature) != chainId) {
                logger.error("Chain ID in signature different from expected chain ID");
                return false;
            }
        } catch (Exception e) {
            logger.error("Could not decode signature");
            return false;
        }
        return true;
    }

    public static boolean verifyKeyAgainstAddress(AsymmetricKeyParameter publicKey, String address) {
        String recoveredAddress = addressFromKey(publicKey);
        return recoveredAddress.equalsIgnoreCase(address);
    }

    public static int getChainIdFromSignature(byte[] signature) {
        byte recoveryByte = signature[64];
        if (recoveryByte == 27 || recoveryByte == 28) {
            return 0;
        }
        // recovery byte is chainId * 2 + 35 for chainId >= 1
        int res= (recoveryByte-35) >> 1;
        return res;
    }

    public static boolean verifySHA256(byte[] unsigned, byte[] signature, AsymmetricKeyParameter key) throws IOException {
        byte[] digestBytes = AttestationCrypto.hashWithSHA256(unsigned);
        return verifyHashed(digestBytes, signature, key);
    }

    public static boolean verifyHashed(byte[] digest, byte[] signature, AsymmetricKeyParameter key) throws IOException {
        ASN1InputStream input = null;
        try {
            input = new ASN1InputStream(signature);
            ASN1Sequence seq = ASN1Sequence.getInstance(input.readObject());
            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            s = normalizeS(s, ((ECKeyParameters) key).getParameters());
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, key);
            return signer.verifySignature(digest, r, s);
        } catch (Exception e) {
            logger.error("Could not decode signature");
            // Something went wrong so the signature cannot be verified
            return false;
        } finally {
            input.close();
        }
    }

    public static AsymmetricKeyParameter recoverEthPublicKeyFromPersonalSignature(byte[] message, byte[] signature) {
        byte[] preHash = convertToPersonalEthMessage(message);
        return recoverEthPublicKeyFromSignature(preHash, signature);
    }

    public static ECPublicKeyParameters recoverEthPublicKeyFromSignature(byte[] message, byte[] signature) {
        byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
        BigInteger r = new BigInteger(1, rBytes);
        if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(SECP256K1_DOMAIN.getN()) >= 1) {
            ExceptionUtil.throwException(logger, new IllegalArgumentException("R value is not in the range [1, n-1]"));
        }
        byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);
        BigInteger s = new BigInteger(1, sBytes);
        if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(SECP256K1_DOMAIN.getN()) >= 1) {
            ExceptionUtil.throwException(logger, new IllegalArgumentException("S value is not in the range [1, n-1]"));
        }
        if (s.compareTo(SECP256K1_DOMAIN.getN().shiftRight(1)) > 0) {
            ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("The s value is not normalized and thus is not allowed by Ethereum EIP2"));
        }
        byte recoveryValue = signature[64];
        byte yParity;
        if (recoveryValue == 0 || recoveryValue == 1) {
            // Handle the edge case where EIP-155 is not supported and the parity bit is stored directly
            yParity = recoveryValue;
        } else {
            // Set parity bit according to EIP-155, i.e. as yParty + chainID * 2 + 35
            yParity = (byte) (1 - (recoveryValue % 2));
        }
        return computePublicKeyFromSignature(new BigInteger[]{r, s}, yParity, message);
    }

    private static ECPublicKeyParameters computePublicKeyFromSignature(BigInteger[] signature, byte yParity, byte[] unsignedMessage) {
        byte[] digestBytes = AttestationCrypto.hashWithKeccak(unsignedMessage);
        BigInteger z = new BigInteger(1, digestBytes);
        // Compute y coordinate for the r value
        ECPoint R = computeY(signature[0], yParity, SECP256K1_DOMAIN);
        BigInteger rInverse = signature[0].modInverse(SECP256K1_DOMAIN.getN());
        BigInteger u1 = z.multiply(rInverse).mod(SECP256K1_DOMAIN.getN());
        BigInteger u2 = signature[1].multiply(rInverse).mod(SECP256K1_DOMAIN.getN());
        ECPoint publicKeyPoint = R.multiply(u2).subtract(SECP256K1_DOMAIN.getG().multiply(u1)).normalize();
        AttestationCrypto.validatePointToCurve(publicKeyPoint, SECP256K1.getCurve());
        return new ECPublicKeyParameters(publicKeyPoint, SECP256K1_DOMAIN);
    }

    private static ECPoint computeY(BigInteger x, byte yParity, ECDomainParameters params) {
        BigInteger P = params.getCurve().getField().getCharacteristic();
        BigInteger A = params.getCurve().getA().toBigInteger();
        BigInteger B = params.getCurve().getB().toBigInteger();
        BigInteger ySquared = x.modPow(new BigInteger("3"), P).
            add(A.multiply(x)).
            add(B).mod(P);
        // We use the Lagrange trick to compute the squareroot (since fieldSize mod 4=3)
        BigInteger y = ySquared.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (y.mod(new BigInteger("2")).byteValueExact() != yParity) {
            y = P.subtract(y);
        }
        return params.getCurve().createPoint(x, y);
    }

    private static BigInteger normalizeS(BigInteger s, ECDomainParameters params) {
        // Normalize number s to be the lowest of its two legal values
        BigInteger half_curve = params.getN().shiftRight(1);
        BigInteger branch = s.compareTo(half_curve) > 0 ? BigInteger.ONE : BigInteger.ZERO;
        // Constant time branch, up to underlying library.
        return (params.getN().subtract(s)).multiply(branch).add((BigInteger.ONE.subtract(branch)).multiply(s));
    }

    /**
     * Constructs a digital signature using a *standard* scheme such as ECDSA with SHA256 or RSA.
     * This method *does not* make signatures that can be directly understood by the Ethreum platform
     *
     * @return The raw signature
     */
    public static byte[] signWithStandardScheme(byte[] unsignedEncoding, AsymmetricCipherKeyPair signingKey) {
        try {
            if (getSigningAlgorithm(signingKey.getPrivate()).equals(ECDSA_WITH_SHA256)) {
                java.security.Signature ecdsaSig = java.security.Signature.getInstance("SHA256withECDSA", "BC");
                ecdsaSig.initSign(
                        SignatureUtility.convertPrivateBouncyCastleKeyToJavaKey(signingKey.getPrivate()));
                ecdsaSig.update(unsignedEncoding);
                return ecdsaSig.sign();
            }
            if (getSigningAlgorithm(signingKey.getPrivate()).equals(RSA_PKCS1)) {
                Security.addProvider(new BouncyCastleProvider());
                java.security.Signature signatureSHA256Java = Signature.getInstance("SHA256WithRSA", "BC");
                signatureSHA256Java.initSign(
                        SignatureUtility.convertPrivateBouncyCastleKeyToJavaKey(signingKey.getPrivate()));
                signatureSHA256Java.update(unsignedEncoding);
                return signatureSHA256Java.sign();
            }
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not perform signing"));
        }
        throw ExceptionUtil.throwException(logger,
                new IllegalArgumentException("Only ECDSA or RSA keys are supported"));
    }

    /**
     * Verified a raw signature against a raw message signed with a *standard* signature scheme.
     */
    public static boolean verifyWithStandardScheme(byte[] msg, byte[] signature, AsymmetricKeyParameter verificationKey) {
        try {
            if (getSigningAlgorithm(verificationKey).equals(ECDSA_WITH_SHA256)) {
                Signature ecdsaSig = Signature.getInstance("SHA256withECDSA", "BC");
                ecdsaSig.initVerify(
                        SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(verificationKey));
                ecdsaSig.update(msg);
                return ecdsaSig.verify(signature);
            }
            if (getSigningAlgorithm(verificationKey).equals(RSA_PKCS1)) {
                Signature signatureSHA256Java = Signature.getInstance("SHA256WithRSA", "BC");
                signatureSHA256Java.initVerify(
                        SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(verificationKey));
                signatureSHA256Java.update(msg);
                return signatureSHA256Java.verify(signature);
            }
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not perform verification"));
        }
        logger.error("Unknown key format");
        return false;
    }

    /**
     * Returns the algorithm to use from a public key to be used for our signature schemes.
     * Currently, this is ECDSA with SHA256 for non secp256k1 ECDSA keys and RSA PKCS 1 1.5 for RSA.
     * For sep256k1 it is ECDSA with recommended parameters.
     */
    public static AlgorithmIdentifier getSigningAlgorithm(AsymmetricKeyParameter signingKey) {
        if (signingKey instanceof ECKeyParameters) {
            if (((ECKeyParameters) signingKey).getParameters().getN().equals(SECP256K1.getN())) {
                // We use secp256k1 so we assume Ethereum signing
                return ECDSA_OID;
            }
            return ECDSA_WITH_SHA256;
        } else if (signingKey instanceof RSAKeyParameters) {
            return RSA_PKCS1;
        } else {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Only ECDSA or RSA keys are supported"));
        }
    }
}
