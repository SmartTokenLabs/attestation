package io.alchemynft.attestation;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.util.HashMap;
import java.util.List;
import org.tokenscript.eip712.Eip712Encoder;

public class NFTAttestationEncoder extends Eip712Encoder {
  private static final String PROTOCOL_VERSION = "0.1";
  private static final String PRIMARY_NAME = "NFTAttestation";//"Signed request to be used only for";
  private static final String USAGE_VALUE = "Single-use Alchemy NFT";

  public NFTAttestationEncoder() {
    super(USAGE_VALUE, PROTOCOL_VERSION, PRIMARY_NAME);
  }

  @Override
  public HashMap<String, List<Entry>> getTypes() {
    return getDefaultTypes();
  }
}
