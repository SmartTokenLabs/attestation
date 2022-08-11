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
import java.util.ArrayList;
import java.util.List;

public class ERC721Token implements ASNEncodable, Validateable {
    private static final Logger logger = LogManager.getLogger(ERC721Token.class);
    public static final long DEFAULT_CHAIN_ID = 0;
    private final byte[] encoding;
    private final String address;
    private final Long chainId;
    private final List<BigInteger> tokenIds;

    public ERC721Token(String address) {
        this(address, (List<BigInteger>) null, DEFAULT_CHAIN_ID);
    }

    public ERC721Token(String address, Long chainId) {
        this(address, (List<BigInteger>) null, chainId);
    }

    public ERC721Token(String address, String tokenId) {
        this(address, new BigInteger(tokenId), DEFAULT_CHAIN_ID);
    }

    public ERC721Token(String address, BigInteger tokenId) {
        this(address, tokenId, DEFAULT_CHAIN_ID);
    }

    public ERC721Token(String address, BigInteger tokenId, Long chainId) {
        this(address, tokenId == null ? null : List.of(tokenId), chainId);
    }

    public ERC721Token(String address, List<BigInteger> tokenIds, Long chainId) {
        this.address = normalizeAddress(address);
        this.tokenIds = tokenIds;
        this.chainId = chainId;
        this.encoding = getDerEncoding(tokenIds != null);
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
            long decodedChainId = ASN1Integer.getInstance(asn1.getObjectAt(counter++)).longValueExact();
            boolean includeTokenId;
            List<BigInteger> decodedTokenIds;
            // The optional tokenIds are included if there is still stuff to decode
            if (asn1.size() > counter) {
                includeTokenId = true;
                ASN1Sequence encodedTokenIds = ASN1Sequence.getInstance(asn1.getObjectAt(counter));
                decodedTokenIds = new ArrayList<>(encodedTokenIds.size());
                for (int i = 0; i < encodedTokenIds.size(); i++) {
                    ASN1OctetString currentTokenId = ASN1OctetString.getInstance(
                            encodedTokenIds.getObjectAt(i));
                    decodedTokenIds.add(
                            new BigInteger(1,
                                    currentTokenId.getOctets()));
                }
            } else {
                // TokenID is not included
                decodedTokenIds = null;
                includeTokenId = false;
            }
            // Remove the # added by BouncyCastle
            String rawAddress = decodedAddress.toString().substring(1);
            this.address = normalizeAddress(rawAddress);
            this.chainId = decodedChainId;
            this.tokenIds = decodedTokenIds;
            this.encoding = getDerEncoding(includeTokenId);
        }
    }

    private void validateTokenIds(List<BigInteger> tokenIds) {
        // The tokenIDs is allowed to be null
        if (tokenIds == null) {
            return;
        }
        getTokenIds().forEach(this::validateTokenId);
    }

    private void validateTokenId(BigInteger tokenId) {
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

    public List<BigInteger> getTokenIds() {
        return tokenIds;
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
            data.add(new ASN1Integer(chainId));
            if (includeTokenId) {
                ASN1EncodableVector tokenIdVector = new ASN1EncodableVector();
                for (BigInteger currentTokenId : tokenIds) {
                    tokenIdVector.add(new DEROctetString(currentTokenId.toByteArray()));
                }
                data.add(new DERSequence(tokenIdVector));
            }
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
            validateTokenIds(getTokenIds());
            validateAddress(getAddress());
        } catch (IllegalArgumentException e) {
            logger.error("Object is not valid");
            return false;
        }
        return true;
    }
}
