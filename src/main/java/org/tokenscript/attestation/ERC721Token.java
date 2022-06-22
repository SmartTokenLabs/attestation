package org.tokenscript.attestation;

import java.io.IOException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.Validateable;
import org.web3j.utils.Numeric;

public class ERC721Token implements ASNEncodable, Validateable {
    private static final Logger logger = LogManager.getLogger(ERC721Token.class);

    private final byte[] encoding;
    private final String address;
    private final Long chainId;
    private final BigInteger tokenId;

    public ERC721Token(String address) {
        this(address, null, null);
    }

    public ERC721Token(String address, Long chainId) {
        this(address, null, chainId);
    }
    public ERC721Token(String address, String tokenId) {
        this(address, new BigInteger(tokenId), null);
    }

    public ERC721Token(String address, BigInteger tokenId)
    {
        this(address, tokenId, null);
    }

    public ERC721Token(String address, BigInteger tokenId, Long chainId) {
        this.address = normalizeAddress(address);
        this.tokenId = tokenId;
        this.chainId = chainId;
        this.encoding = getDerEncoding(tokenId != null, chainId != null);
        constructorCheck();
    }

    private void constructorCheck() {
        if (!checkValidity()) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not validate object"));
        }
    }

    private void validateChainId(Long chainId) {
        // ChainID is optional
        if (chainId == null) {
            return;
        }
        if (chainId < 0) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Chain ID cannot be negative"));
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
        if (tokenId.compareTo(new BigInteger("2").pow(256)) >= 0) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Token ID too large"));
        }
    }

    /**
     * Validates and normalizes address to lower case with `0x` prefix.
     * @param address
     * @return
     */
    private String normalizeAddress(String address) {
        // Convert address to lowercase and add "0x" prefix if not there
        return address.length() < 42 ? "0x" + address.toLowerCase() : address.toLowerCase();
    }

    public void validateAddress(String address) {
        // 0x plus 20 bytes, each byte using 2 chars in hex
        if (address.length() != 40+2) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Not a valid address. Incorrect length"));
        }
        try {
            // Try to decode to ensure it is hex (after removing the "0x" prefix)
            Hex.decode(address.substring(2, address.length()));
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Not a valid address. Not hex encoded"));
        }
    }

    public ERC721Token(byte[] derEncoding) throws IOException {
        ASN1InputStream input = null;
        try {
            int counter = 0;
            input = new ASN1InputStream(derEncoding);
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
            ASN1OctetString address = DEROctetString.getInstance(asn1.getObjectAt(counter++));
            BigInteger tokenId;
            boolean includeTokenId;
            try {
                ASN1OctetString tokenIdObject = DEROctetString.getInstance(asn1.getObjectAt(counter));
                tokenId = new BigInteger(1, tokenIdObject.getOctets());
                validateTokenId(tokenId);
                includeTokenId = true;
                counter++;
            } catch (Exception e) {
                // TokenID is not included
                tokenId = null;
                includeTokenId = false;
            }
            Long chainId;
            boolean includeChainId;
            try {
                chainId = ASN1Integer.getInstance(asn1.getObjectAt(counter++)).longValueExact();
                includeChainId = true;
            } catch (Exception e) {
                // Chain Id not included, so set it to default
                chainId = null;
                includeChainId = false;
            }
            // Remove the # added by BouncyCastle
            String rawAddress = address.toString().substring(1);
            this.address = normalizeAddress(rawAddress);
            this.tokenId = tokenId;
            this.chainId = chainId;
            this.encoding = getDerEncoding(includeTokenId, includeChainId);
        } finally {
            input.close();
        }
        constructorCheck();
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
    public byte[] getDerEncoding()
    {
        return encoding;
    }

    public byte[] getDerEncoding(boolean includeTokenId, boolean includeChainId)
    {
        return getTokenVector(includeTokenId, includeChainId);
    }

    public byte[] getTokenVector(boolean includeTokenId, boolean includeChainId) {
        try {
            ASN1EncodableVector data = new ASN1EncodableVector();
            data.add(new DEROctetString(Numeric.hexStringToByteArray(address)));
            if (includeTokenId) {
                data.add(new DEROctetString(tokenId.toByteArray()));
            }
            if (includeChainId) {
                data.add(new ASN1Integer(chainId));
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
            validateTokenId(getTokenId());
            validateAddress(getAddress());
        } catch (IllegalArgumentException e) {
            logger.error("Object is not valid");
            return false;
        }
        return true;
    }
}
