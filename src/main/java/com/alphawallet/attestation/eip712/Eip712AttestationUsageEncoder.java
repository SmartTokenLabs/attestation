package com.alphawallet.attestation.eip712;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.FullEip712InternalData;

public class Eip712AttestationUsageEncoder extends Eip712Encoder {
  static final String PROTOCOL_VERSION = "0.1";

  static final String PRIMARY_NAME = "AttestationUsage";
  static final String USAGE_VALUE = "Prove that the \"identity\" is the identity hidden in attestation contained in\"payload\".";

  public Eip712AttestationUsageEncoder(long chainId) {
    super(PROTOCOL_VERSION, PRIMARY_NAME, chainId);
  }

  @Override
  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = getDefaultTypes();
    types.get(PRIMARY_NAME).add(IDENTIFIER_ENTRY);
    return types;
  }

  static class AttestationUsageData extends FullEip712InternalData {
    private String identifier;
    private String expirationTime;

    public AttestationUsageData() { super(); }

    public AttestationUsageData(String description, String identifier, String payload, long timeStamp, long expirationTime) {
      super(description, payload, timestampFormat.format(new Date(timeStamp)));
      this.identifier = identifier;
      this.expirationTime = timestampFormat.format(new Date(expirationTime));
    }

    public AttestationUsageData(String description, String identifier, String payload, String timeStamp, String expirationTime) {
      super(description, payload, timeStamp);
      this.identifier = identifier;
      this.expirationTime = expirationTime;
    }

    public String getIdentifier() {
      return identifier;
    }

    public void setIdentifier(String identifier) {
      this.identifier = identifier;
    }

    public String getExpirationTime() { return expirationTime; }

    public void setExpirationTime(String expirationTime) { this.expirationTime = expirationTime; }

    @JsonIgnore
    @Override
    public AttestationUsageData getSignableVersion() {
      return new AttestationUsageData(getDescription(), getIdentifier(), Eip712Encoder.computePayloadDigest(getPayload()), getTimestamp(), getExpirationTime());
    }
  }
}
