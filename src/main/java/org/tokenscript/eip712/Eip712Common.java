package org.tokenscript.eip712;

import com.alphawallet.token.web.service.CryptoFunctions;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Common class for EIP712 JSON issuance and validation
 */
public abstract class Eip712Common {
  protected final CryptoFunctions cryptoFunctions;
  protected final ObjectMapper mapper;
  protected final Eip712Encoder encoder;

  public Eip712Common(Eip712Encoder encoder) {
    Security.addProvider(new BouncyCastleProvider());
    this.cryptoFunctions = new CryptoFunctions();
    this.mapper = new ObjectMapper();
    mapper.setSerializationInclusion(Include.NON_NULL);
    this.encoder = encoder;
  }

  public static boolean isDomainValid(String domain) {
    try {
      // Check if we get a malformed exception
      new URL(domain);
    } catch (MalformedURLException e) {
      return false;
    }
    return true;
  }
}
