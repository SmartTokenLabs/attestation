package org.tokenscript.eip712;

import com.alphawallet.attestation.core.AttestationCrypto;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Hex;

public class SignableEip712InternalData extends Eip712InternalData {
  private String payloadDigest;

  public SignableEip712InternalData(FullEip712InternalData fullData) {
    super(fullData.getDescription(), fullData.getTimeStamp());
    this.payloadDigest = Hex.toHexString(AttestationCrypto.hashWithKeccak(fullData.getPayload().getBytes(StandardCharsets.UTF_8)));
  }

  public SignableEip712InternalData() {}

  public SignableEip712InternalData(String description, String payloadDigest, String timeStamp) {
    super(description, timeStamp);
    this.payloadDigest = payloadDigest;
  }

  public String getPayloadDigest() {
    return payloadDigest;
  }

  public void setPayloadDigest(String payloadDigest) {
    this.payloadDigest = payloadDigest;
  }
}
