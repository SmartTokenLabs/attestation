package org.tokenscript.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;

public class UseAttestableRequest {
  private byte[] useAttestableRequest;
  private long timeStamp;
  private String domain;
  private byte[] auxiliary;
  private byte[] signature;

  public UseAttestableRequest() {}

  public UseAttestableRequest(byte[] useAttestableRequest, long timeStamp, String domain,
      byte[] auxiliary) {
    this.useAttestableRequest = useAttestableRequest;
    this.timeStamp = timeStamp;
    this.domain = domain;
    this.auxiliary = auxiliary;
  }

  public UseAttestableRequest(byte[] useAttestableRequest, long timeStamp, String domain,
      byte[] auxiliary, byte[] signature) {
    this.useAttestableRequest = useAttestableRequest;
    this.timeStamp = timeStamp;
    this.domain = domain;
    this.auxiliary = auxiliary;
    this.signature = signature;
  }

  public byte[] getUseAttestableRequest() {
    return useAttestableRequest;
  }

  public void setUseAttestableRequest(byte[] useAttestableRequest) {
    this.useAttestableRequest = useAttestableRequest;
  }

  public long getTimeStamp() {
    return timeStamp;
  }

  public void setTimeStamp(long timeStamp) {
    this.timeStamp = timeStamp;
  }

  public String getDomain() {
    return domain;
  }

  public void setDomain(String domain) {
    this.domain = domain;
  }

  public byte[] getAuxiliary() {
    return auxiliary;
  }

  public void setAuxiliary(byte[] auxiliary) {
    this.auxiliary = auxiliary;
  }

  public byte[] getSignature() {
    return signature;
  }

  public void setSignature(byte[] signature) {
    this.signature = signature;
  }

  @JsonIgnore
  public byte[] getSignable() {
    try {
      ASN1EncodableVector signable = new ASN1EncodableVector();
      signable.add(new DEROctetString(useAttestableRequest));
      signable.add(new ASN1Integer(timeStamp));
      signable.add(new DERPrintableString(domain));
      signable.add(new DEROctetString(auxiliary));
      return new DERSequence(signable).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
