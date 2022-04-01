package org.devcon.ticket;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.ExceptionUtil;

/**
 * Wrapper class that allows decoding of either Devcon or Liscon tickets.
 * This class only exists for backward compatibility reasons
 */
@Deprecated
public class TicketDecoder implements ObjectDecoder<Ticket> {
  private static final Logger logger = LogManager.getLogger(TicketDecoder.class);
  private final List<ObjectDecoder<Ticket>> decoders = new ArrayList<>(2);

  public TicketDecoder(Map<String, AsymmetricKeyParameter> idsToKeys) {
    decoders.add(new DevconTicketDecoder(idsToKeys));
  }

  public TicketDecoder(AsymmetricKeyParameter publicKey) {
    decoders.add(new DevconTicketDecoder(publicKey));
    decoders.add(new LisconTicketDecoder(publicKey));
  }

  @Override
  public Ticket decode(byte[] encoding) throws IOException {
    for (ObjectDecoder<Ticket> currentDecoder : decoders) {
      try {
        return currentDecoder.decode(encoding);
      } catch (Exception e) {
        continue;
      }
    }
    ExceptionUtil.throwException(logger, new RuntimeException("Could not decode ticket"));
    return null;
  }
}
