package com.alphawallet.attestation.core;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class SignatureUtility {
    public static final String ECDSA_CURVE = "secp256k1";
    public static final String MAC_ALGO = "HmacSHA256";
    public static final ASN1ObjectIdentifier OID_SIGNATURE_ALG = new ASN1ObjectIdentifier("1.2.840.10045.2.1"); // OID for elliptic curve crypto ecPublicKey
    public static final AlgorithmIdentifier ALGORITHM_IDENTIFIER = new AlgorithmIdentifier(OID_SIGNATURE_ALG);
    public static final X9ECParameters ECDSACurve = SECNamedCurves.getByName(ECDSA_CURVE);
    public static final ECDomainParameters ECDSAdomain = new ECDomainParameters(ECDSACurve.getCurve(), ECDSACurve.getG(), ECDSACurve.getN(), ECDSACurve.getH());

    private static final String ethereumPrefix = "\u0019Ethereum Signed Message:\n";

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
        BigInteger fieldModulo = ECDSAdomain.getCurve().getField()
            .getCharacteristic();
        // If the y coordinate is in the upper half of the field, then sample again until it to the lower half
        do {
            keys = constructECKeys(rand);
            ECPublicKeyParameters pk = (ECPublicKeyParameters) keys.getPublic();
            yCoord = pk.getQ().getYCoord().toBigInteger();
        } while (yCoord.compareTo(fieldModulo.shiftRight(1)) > 0);
        return keys;
    }
    /**
     * Construct default keys; secp256k1
     * @param random
     */
    public static AsymmetricCipherKeyPair constructECKeys(SecureRandom random) {
        return constructECKeys(ECDSAdomain, random);
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
        AlgorithmIdentifier identifierEnc = new AlgorithmIdentifier(
            SignatureUtility.OID_SIGNATURE_ALG, SignatureUtility.ECDSACurve.toASN1Primitive());
        return restoreDefaultKey(identifierEnc, input);
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

    /**
     * Code shamelessly stolen from https://medium.com/@fixone/ecc-for-ethereum-on-android-7e35dc6624c9
     * But then fixed due to a bug in that code.
     * @param key
     * @return
     */
    public static String addressFromKey(AsymmetricKeyParameter key) {
        byte[] pubKey;
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
            pubKey = spki.getPublicKeyData().getOctets();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //discard the first byte which only tells what kind of key it is //i.e. encoded/un-encoded
        pubKey = Arrays.copyOfRange(pubKey,1,pubKey.length);
        byte[] hash = AttestationCrypto.hashWithKeccak(pubKey);
        //finally get only the last 20 bytes
        return "0x" + Hex.toHexString(Arrays.copyOfRange(hash,hash.length-20,hash.length)).toUpperCase();
    }

    public static byte[] signWithEthereum(byte[] unsigned, AsymmetricCipherKeyPair keys) {
        return signWithEthereum(unsigned, 0, keys);
    }

    public static byte[] signWithEthereum(byte[] unsigned, int chainID, AsymmetricCipherKeyPair keys) {
        byte[] toSign = addPersonalSignPrefix(unsigned);
        BigInteger[] signature = computeInternalSignature(toSign, (ECPrivateKeyParameters) keys.getPrivate());
        return normalizeAndEncodeEthereumSignature(signature, chainID);
    }

    /**
     * Constructs a DER encoded, non-malleable deterministic ECDSA signature using Keccak256
     * That is, n accordance with EIP 2 (the y-coordinate is guaranteed to be <n/2).
     * The deterministic approach used is the one from RFC 6979
     * @param toSign
     * @param key
     * @return
     */
    public static byte[] signDeterministic(byte[] toSign, AsymmetricKeyParameter key) {
        BigInteger[] signature = computeInternalSignature(toSign, (ECPrivateKeyParameters) key);
        return normalizeAndEncodeDerSignature(signature, ((ECKeyParameters) key).getParameters());
    }

    /**
     * Constructs a DER encoded indeterministic (randomized) ECDSA signature based on an already hashed value.
     * Despite being randomized this is done in accordance with EIP 2 (the y-coordinate is guaranteed to be <n/2)
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
            throw new RuntimeException(e);
        }
    }

    /**
     * Computes a signature as an internal representation.
     * Specifically as a BigInteger array containing {r, s, v}, where v is the parity
     * of the y-coordinate of the curve point r is computed from.
     * @return The signature as {r, s, v} where v is the y-parity of R.
     */
    static BigInteger[] computeInternalSignature(byte[] toSign, ECPrivateKeyParameters key) {
        byte[] digest = AttestationCrypto.hashWithKeccak(toSign);
        BigInteger z = new BigInteger(1, digest);

        HMacDSAKCalculator randomnessProvider = new HMacDSAKCalculator(new KeccakDigest(256));
        randomnessProvider.init(key.getParameters().getN(), key.getD(), digest);

        BigInteger n = key.getParameters().getN();
        BigInteger r, k;
        ECPoint R;
        do {
            k = randomnessProvider.nextK();
            R = key.getParameters().getG().multiply(k).normalize();
            r = R.getAffineXCoord().toBigInteger().mod(n);
        } while (r.equals(BigInteger.ZERO));
        BigInteger baseS = k.modInverse(n).multiply(z.add(r.multiply(key.getD()))).mod(n);
        BigInteger normalizedS = normalizeS(baseS, key.getParameters());
        BigInteger v = R.getAffineYCoord().toBigInteger().mod(new BigInteger("2"));
        // Normalize parity in case s needs normalization
        if (!normalizedS.equals(baseS)) {
            // Flip the bit value
            v = BigInteger.ONE.subtract(v);
        }
        return new BigInteger[] {r, normalizedS, v};
    }

    private static byte[] addPersonalSignPrefix(byte[] msgToSign) {
        String hexMsg = "0x" + Hex.toHexString(msgToSign);
        String ethereumMsg = ethereumPrefix + hexMsg.length() + hexMsg;
        return ethereumMsg.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] normalizeAndEncodeEthereumSignature(BigInteger[] signature, int chainID) {
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
    private static byte computeRecoveryValue(BigInteger v, int chainID) {
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
    public static boolean verifyEthereumSignature(byte[] unsigned, byte[] signature, AsymmetricKeyParameter publicKey) {
        return verifyEthereumSignature(unsigned, signature, addressFromKey(publicKey));
    }

    /**
     * Verify an Ethereum signature against an address on a message that DOES NOT include the signed-by-Ethereum prefix when used outside of the blockchain
     */
    public static boolean verifyEthereumSignature(byte[] unsigned, byte[] signature, String address) {
        try {
            byte[] unsignedWithEthPrefix = addPersonalSignPrefix(unsigned);
            ECPublicKeyParameters publicKey = recoverEthPublicKeyFromSignature(
                unsignedWithEthPrefix, signature);
            String recoveredAddress = addressFromKey(publicKey);
            return recoveredAddress.toUpperCase().equals(address.toUpperCase());
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean verify(byte[] unsigned, byte[] signature, AsymmetricKeyParameter key) {
        byte[] digestBytes = AttestationCrypto.hashWithKeccak(unsigned);
        return verifyHashed(digestBytes, signature, key);
    }

    public static boolean verifyHashed(byte[] digest, byte[] signature, AsymmetricKeyParameter key) {
        try {
            ASN1InputStream input = new ASN1InputStream(signature);
            ASN1Sequence seq = ASN1Sequence.getInstance(input.readObject());
            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            s = normalizeS(s, ((ECKeyParameters) key).getParameters());
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, key);
            return signer.verifySignature(digest, r, s);
        } catch (Exception e) {
            // Something went wrong so the signature cannot be verified
            return false;
        }
    }

    public static ECPublicKeyParameters recoverEthPublicKeyFromSignature(byte[] unsigned, byte[] signature) {
        byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
        BigInteger r = new BigInteger(1, rBytes);
        byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);
        BigInteger s = new BigInteger(1, sBytes);
        if (s.compareTo(ECDSAdomain.getN().shiftRight(1)) > 0) {
            throw new IllegalArgumentException("The s value is not normalized and thus is not allowed by Ethereum EIP2");
        }
        byte recoveryValue = signature[64];
        byte yParity = (byte) (1 - (recoveryValue % 2));
        return computePublicKeyFromSignature(new BigInteger[]{r, s}, yParity, unsigned);
    }

    private static ECPublicKeyParameters computePublicKeyFromSignature(BigInteger[] signature, byte yParity, byte[] unsignedMessage) {
        byte[] digestBytes = AttestationCrypto.hashWithKeccak(unsignedMessage);
        BigInteger z = new BigInteger(1, digestBytes);
        // Compute y coordinate for the r value
        ECPoint R = computeY(signature[0], yParity, ECDSAdomain);
        BigInteger rInverse = signature[0].modInverse(ECDSAdomain.getN());
        BigInteger u1 = z.multiply(rInverse).mod(ECDSAdomain.getN());
        BigInteger u2 = signature[1].multiply(rInverse).mod(ECDSAdomain.getN());
        ECPoint publicKeyPoint = R.multiply(u2).subtract(ECDSAdomain.getG().multiply(u1)).normalize();
        return new ECPublicKeyParameters(publicKeyPoint, ECDSAdomain);
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
        BigInteger half_curve = params.getCurve().getOrder().shiftRight(1);
        if (s.compareTo(half_curve) > 0) {
            return params.getN().subtract(s);
        }
        return s;
    }
}
