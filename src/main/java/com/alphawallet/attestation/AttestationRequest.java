package com.alphawallet.attestation;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class AttestationRequest implements ASNEncodable, Verifiable {
  private static final Logger logger = LogManager.getLogger(AttestationRequest.class);
  private final AttestationType type;
  private final FullProofOfExponent pok;

  public AttestationRequest(AttestationType type, FullProofOfExponent pok) {
    this.type = type;
    this.pok = pok;

    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify"));
    }
  }

  public AttestationRequest(byte[] derEncoding) {
    try {
      ASN1InputStream input = new ASN1InputStream(derEncoding);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      int i = 0;
      this.type = AttestationType.values()[
          ASN1Integer.getInstance(asn1.getObjectAt(i++)).getValue().intValueExact()];
      this.pok = new FullProofOfExponent(
          ASN1Sequence.getInstance(asn1.getObjectAt(i++)).getEncoded());
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Signature is not valid"));
    }
  }

  public AttestationType getType() { return type; }

  public FullProofOfExponent getPok() { return pok; }

  @Override
  public byte[] getDerEncoding() {
    try {
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(new ASN1Integer(type.ordinal()));
      res.add(ASN1Primitive.fromByteArray(pok.getDerEncoding()));
      return new DERSequence(res).getEncoded();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
  }

  @Override
  public boolean verify() {
    if (!AttestationCrypto.verifyFullProof(pok)) {
      logger.error("Could not verify proof of knowledge");
      return false;
    }
    return true;
  }
}
