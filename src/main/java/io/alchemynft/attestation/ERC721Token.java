package io.alchemynft.attestation;

import java.io.IOException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.web3j.utils.Numeric;

/**
 * Legacy class only used in Alchemy nft attestation. For any other use, use ERC721Token from
 * org.tokenscript.attestation
 */
@Deprecated
public class ERC721Token implements ASNEncodable {

  private static final Logger logger = LogManager.getLogger(ERC721Token.class);

  private final byte[] encoding;
  private final String address;
  private final BigInteger tokenId;

  public ERC721Token(String address, String tokenId) {
    this.address = address.toLowerCase();
    BigInteger tokenIdInteger;
    try {
      tokenIdInteger = new BigInteger(tokenId);
    } catch (Exception e) {
      tokenIdInteger = BigInteger.ZERO;
    }
    validateID(tokenIdInteger);
    this.tokenId = tokenIdInteger;
    this.encoding = constructEncoding();
  }

  public ERC721Token(String address, BigInteger tokenId) {
    this.address = address.toLowerCase();
    validateID(tokenId);
    this.tokenId = tokenId;
    this.encoding = constructEncoding();
  }

  public ERC721Token(byte[] derEncoding) throws IOException {
    ASN1InputStream input = null;
    try {
      input = new ASN1InputStream(derEncoding);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      ASN1OctetString address = DEROctetString.getInstance(asn1.getObjectAt(0));
      ASN1OctetString tokenId = DEROctetString.getInstance(asn1.getObjectAt(1));
      // Remove the # added by BouncyCastle
      this.address = address.toString().substring(1);
      this.tokenId = new BigInteger(1, tokenId.getOctets());
      this.encoding = constructEncoding();
    } finally {
      input.close();
    }
  }

  private void validateID(BigInteger tokenId) {
    // Only allow non-negative IDs
    if (tokenId.compareTo(BigInteger.ZERO) < 0) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("IDs cannot be negative"));
    }
  }

  public String getAddress() {
    return address;
  }

  public BigInteger getTokenId() {
    return tokenId;
  }


  @Override
  public byte[] getDerEncoding() {
    return encoding;
  }

  byte[] constructEncoding() {
    ASN1EncodableVector data = getTokenVector();
    try {
      return new DERSequence(data).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public ASN1EncodableVector getTokenVector() {
    ASN1EncodableVector data = new ASN1EncodableVector();
    data.add(new DEROctetString(Numeric.hexStringToByteArray(address)));
    data.add(new DEROctetString(tokenId.toByteArray()));
    return data;
  }
}