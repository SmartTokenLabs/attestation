package org.tokenscript.attestation;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.CapabilityAttestation.CapabilityType;

public class CapabilityAttestationDecoder implements AttestableObjectDecoder<CapabilityAttestation>{
  private static final Logger logger = LogManager.getLogger(CapabilityAttestationDecoder.class);
  private static final String DEFAULT = "default";

  private Map<String, AsymmetricKeyParameter> idsToKeys = new HashMap<>();

  public CapabilityAttestationDecoder(Map<String, AsymmetricKeyParameter> idsToKeys) {
    this.idsToKeys = idsToKeys;
  }

  public CapabilityAttestationDecoder(AsymmetricKeyParameter publicKey) {
    idsToKeys.put(DEFAULT, publicKey);
  }

  @Override
  public CapabilityAttestation decode(byte[] encoding) throws IOException {
    ASN1InputStream input = new ASN1InputStream(encoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    input.close();
    ASN1Sequence capabilityAttestation = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    int innerCtr = 0;
    BigInteger uniqueId = (ASN1Integer.getInstance(capabilityAttestation.getObjectAt(innerCtr++))).getValue();
    String sourceDomain = DERUTF8String.getInstance(capabilityAttestation.getObjectAt(innerCtr++)).getString();
    String targetDomain = DERUTF8String.getInstance(capabilityAttestation.getObjectAt(innerCtr++)).getString();
    long notBeforeLong = (ASN1Integer.getInstance(capabilityAttestation.getObjectAt(innerCtr++))).getValue().longValueExact();
    Instant notBefore =  Instant.ofEpochSecond(notBeforeLong /1000);
    long notAfterLong = (ASN1Integer.getInstance(capabilityAttestation.getObjectAt(innerCtr++))).getValue().longValueExact();
    Instant notAfter =  Instant.ofEpochSecond(notAfterLong /1000);
    byte[] capabilityBytes = DERBitString.getInstance(capabilityAttestation.getObjectAt(innerCtr++)).getBytes();
    Set<CapabilityType> capabilities = convertToSet(capabilityBytes);
    byte[] signature = DERBitString.getInstance(asn1.getObjectAt(1)).getBytes();
    return new CapabilityAttestation(uniqueId, sourceDomain, targetDomain, notBefore,
        notAfter, capabilities, signature, getPk(sourceDomain));
  }

  static Set<CapabilityType> convertToSet(byte[] capabilityBytes) {
    Set<CapabilityType> capabilitySet = new HashSet<>();
    BitSet bitSet = BitSet.valueOf(capabilityBytes);
    int lastBitIndex = 0;
    while (bitSet.nextSetBit(lastBitIndex) != -1) {
      int currentBitIndex = bitSet.nextSetBit(lastBitIndex);
      CapabilityType currentType = CapabilityType.getType(currentBitIndex);
      capabilitySet.add(currentType);
      lastBitIndex = currentBitIndex+1;
    }
    return capabilitySet;
  }

  private AsymmetricKeyParameter getPk(String sourceDomain) {
    AsymmetricKeyParameter pk;
    if (idsToKeys.get(sourceDomain) != null) {
      pk = idsToKeys.get(sourceDomain);
    } else {
      pk = idsToKeys.get(DEFAULT);
    }
    return pk;
  }
}
