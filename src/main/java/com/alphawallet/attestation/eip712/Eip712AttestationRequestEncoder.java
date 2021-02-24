package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.eip712.Eip712Encoder;
import org.web3j.abi.datatypes.Address;

public class Eip712AttestationRequestEncoder implements Eip712Encoder {
  static final String PROTOCOL_VERSION = "0.1";

  static final String PRIMARY_NAME = "AttestationRequest";
  static final String DESCRIPTION_NAME = "description";
  static final String PAYLOAD_NAME = "payload";
  static final String IDENTITY_NAME = "identity";
  static final String ADDRESS_NAME = "address";
  static final String TIMESTAMP_NAME = "timestamp";//"Timestamp (milliseconds since epoch)";

  static final String USAGE_VALUE = "Linking Ethereum address to phone or email";

  public Eip712AttestationRequestEncoder() {
  }

  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = new HashMap<>();
    List<Entry> content = new ArrayList<>();
    content.add(new Entry(PAYLOAD_NAME, STRING));
    content.add(new Entry(DESCRIPTION_NAME, STRING));
    content.add(new Entry(IDENTITY_NAME, STRING));
    content.add(new Entry(ADDRESS_NAME, ADDRESS));
    content.add(new Entry(TIMESTAMP_NAME, UINT64));
    types.put(PRIMARY_NAME, content);
    List<Entry> domainContent = new ArrayList<>();
    domainContent.add(new Entry("name", STRING));
    domainContent.add(new Entry("version", STRING));
//    domainContent.add(new Entry("chainId", UINT256));
//    domainContent.add(new Entry("verifyingContract", ADDRESS));
//    domainContent.add(new Entry("salt", BYTES32));
    types.put("EIP712Domain", domainContent);
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

  static class AttestationRequestData {
    private String description;
    private String identifier;
    // TODO This should actually be of type Address, but currently this type of the web3j is not Jackson serializable
    private String address;
    private String payload;
    private long timeStamp;

    public AttestationRequestData() {}

    public AttestationRequestData(String description, String identifier, String address, String payload, long timeStamp) {
      this.description = description;
      this.identifier = identifier;
      this.address = address;
      this.payload = payload;
      this.timeStamp = timeStamp;
    }

    public String getDescription() {
      return description;
    }

    public void setDescription(String description) {
      this.description = description;
    }

    public String getIdentifier() {
      return identifier;
    }

    public void setIdentifier(String identifier) {
      this.identifier = identifier;
    }

    public String getAddress() {
      return address;
    }

    public void setAddress(String address) {
      this.address = address;
    }

    public String getPayload() {
      return payload;
    }

    public void setPayload(String payload) {
      this.payload = payload;
    }

    public long getTimeStamp() {
      return timeStamp;
    }

    public void setTimeStamp(long timeStamp) {
      this.timeStamp = timeStamp;
    }
  }
}
