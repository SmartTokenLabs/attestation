package org.tokenscript.eip712;

public class Eip712ExternalData {
  private String signatureInHex;
  private String jsonSigned;

  public Eip712ExternalData() {}

  public Eip712ExternalData(String signatureInHex, String jsonSigned) {
    this.signatureInHex = signatureInHex;
    this.jsonSigned = jsonSigned;
  }

  public String getSignatureInHex() {
    return signatureInHex;
  }

  public void setSignatureInHex(String signatureInHex) {
    this.signatureInHex = signatureInHex;
  }

  public String getJsonSigned() {
    return jsonSigned;
  }

  public void setJsonSigned(String jsonSigned) {
    this.jsonSigned = jsonSigned;
  }
}
