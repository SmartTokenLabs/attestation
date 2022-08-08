package org.tokenscript.attestation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.Validateable;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;

public class ERC721Token implements ASNEncodable, Validateable {
    private static final Logger logger = LogManager.getLogger(ERC721Token.class);
    public static final long DEFAULT_CHAIN_ID = 0;
    private final byte[] encoding;
    private final String address;
    private final Long chainId;
    private final BigInteger tokenId;

    public ERC721Token(String address) {
        this(address, null, DEFAULT_CHAIN_ID);
    }

    public ERC721Token(String address, Long chainId) {
        this(address, null, chainId);
    }
    public ERC721Token(String address, String tokenId) {
        this(address, new BigInteger(tokenId), DEFAULT_CHAIN_ID);
    }

    public ERC721Token(String address, BigInteger tokenId)
    {
        this(address, tokenId, DEFAULT_CHAIN_ID);
    }

    public ERC721Token(String address, BigInteger tokenId, Long chainId) {
        this.address = normalizeAddress(address);
        this.tokenId = tokenId;
        this.chainId = chainId;
        this.encoding = getDerEncoding(tokenId != null);
    }

    private void validateChainId(Long chainId) {
        if (chainId < 0) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Chain ID cannot be negative"));
        }
    }

    public ERC721Token(byte[] derEncoding) throws IOException {
        int counter = 0;
        try (ASN1InputStream input = new ASN1InputStream(derEncoding)) {
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
            ASN1OctetString decodedAddress = ASN1OctetString.getInstance(asn1.getObjectAt(counter++));
            BigInteger decodedTokenId;
            boolean includeTokenId;
            try {
                ASN1OctetString tokenIdObject = ASN1OctetString.getInstance(asn1.getObjectAt(counter));
                decodedTokenId = new BigInteger(1, tokenIdObject.getOctets());
                validateTokenId(decodedTokenId);
                includeTokenId = true;
                counter++;
            } catch (Exception e) {
                // TokenID is not included
                decodedTokenId = null;
                includeTokenId = false;
            }
            this.chainId = ASN1Integer.getInstance(asn1.getObjectAt(counter++)).longValueExact();
            // Remove the # added by BouncyCastle
            String rawAddress = decodedAddress.toString().substring(1);
            this.address = normalizeAddress(rawAddress);
            this.tokenId = decodedTokenId;
            this.encoding = getDerEncoding(includeTokenId);
        }
    }

    private void validateTokenId(BigInteger tokenId) {
        // The tokenID is allowed to be null
        if (tokenId == null) {
            return;
        }
        // Only allow non-negative IDs
        if (tokenId.compareTo(BigInteger.ZERO) < 0) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Token IDs cannot be negative"));
        }
        // ID cannot be more than 256 bits
        if (tokenId.compareTo(BigInteger.valueOf(2).pow(256)) >= 0) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Token ID too large"));
        }
    }

    // TODO move to util class
    public static void validateAddress(String address) {
        // 0x plus 20 bytes, each byte using 2 chars in hex
        if (address.length() != 40 + 2) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Not a valid address. Incorrect length"));
        }
        try {
            // Try to decode to ensure it is hex (after removing the "0x" prefix)
            Hex.decode(address.substring(2));
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Not a valid address. Not hex encoded"));
        }
    }

    /**
     * Validates and normalizes address to lower case with `0x` prefix.
     *
     * @param address Potentially unnormalized address to normalize
     * @return Normalized address
     */
    private String normalizeAddress(String address) {
        // Convert address to lowercase and add "0x" prefix if not there
        return address.length() < 42 ? "0x" + address.toLowerCase() : address.toLowerCase();
    }

    public String getAddress() {
        return address;
    }

    public BigInteger getTokenId() {
        return tokenId;
    }

    public Long getChainId() {
        return chainId;
    }

    @Override
    public byte[] getDerEncoding() {
        return encoding;
    }
    // todo override equals and implement tests

    public byte[] getDerEncoding(boolean includeTokenId) {
        return getTokenVector(includeTokenId);
    }

    public byte[] getTokenVector(boolean includeTokenId) {
        try {
            ASN1EncodableVector data = new ASN1EncodableVector();
            data.add(new DEROctetString(Numeric.hexStringToByteArray(address)));
            if (includeTokenId) {
                data.add(new DEROctetString(tokenId.toByteArray()));
            }
            data.add(new ASN1Integer(chainId));
            return new DERSequence(data).getEncoded();
        } catch (IOException e) {
            throw ExceptionUtil.throwException(logger,
                    new RuntimeException("Failure during asn1 encoding"));
        }
    }

    @Override
    public boolean checkValidity() {
        try {
            validateChainId(getChainId());
            validateTokenId(getTokenId());
            validateAddress(getAddress());
        } catch (IllegalArgumentException e) {
            logger.error("Object is not valid");
            return false;
        }
        return true;
    }
}
