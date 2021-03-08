package org.tokenscript.eip712;

public class Eip712ExternalData {
  private String signatureInHex;
  // jsonRPC and chainID are needed to be compliant with EIP712 https://eips.ethereum.org/EIPS/eip-712
  private String jsonRpc;
  private int chainId;
  private String jsonSigned;

  public Eip712ExternalData() {}

  public Eip712ExternalData(String signatureInHex, String jsonRpc, int chainId, String jsonSigned) {
    this.signatureInHex = signatureInHex;
    this.jsonRpc = jsonRpc;
    this.chainId = chainId;
    this.jsonSigned = jsonSigned;
  }

  public String getSignatureInHex() {
    return signatureInHex;
  }

  public void setSignatureInHex(String signatureInHex) {
    this.signatureInHex = signatureInHex;
  }

  public String getJsonRpc() {
    return jsonRpc;
  }

  public void setJsonRpc(String jsonRpc) {
    this.jsonRpc = jsonRpc;
  }

  public int getChainId() {
    return chainId;
  }

  public void setChainId(int chainId) {
    this.chainId = chainId;
  }

  public String getJsonSigned() {
    return jsonSigned;
  }

  public void setJsonSigned(String jsonSigned) {
    this.jsonSigned = jsonSigned;
  }
}
