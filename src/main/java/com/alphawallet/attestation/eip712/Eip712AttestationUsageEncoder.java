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

  public Eip712AttestationUsageEncoder() {
  }

  @Override
  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = getDefaultTypes(PRIMARY_NAME);
    types.get(PRIMARY_NAME).add(IDENTIFIER_ENTRY);
    return types;
  }

  @Override
  public String getPrimaryName() {
    return PRIMARY_NAME;
  }

  @Override
  public String getProtocolVersion() {
    return PROTOCOL_VERSION;
  }

  @Override
  public String getSalt() {
    return null;
  }

  static class AttestationUsageData extends FullEip712InternalData {
    private String identifier;

    public AttestationUsageData() { super(); }

    public AttestationUsageData(String description, String identifier, String payload, long timeStamp) {
      super(description, payload, timestampFormat.format(new Date(timeStamp)));
      this.identifier = identifier;
    }

    public AttestationUsageData(String description, String identifier, String payload, String timeStamp) {
      super(description, payload, timeStamp);
      this.identifier = identifier;
    }

    public String getIdentifier() {
      return identifier;
    }

    public void setIdentifier(String identifier) {
      this.identifier = identifier;
    }

    @JsonIgnore
    @Override
    public AttestationUsageData getSignableVersion() {
      return new AttestationUsageData(getDescription(), getIdentifier(), Eip712Encoder.computePayloadDigest(getPayload()), getTimestamp());
    }
  }
}
