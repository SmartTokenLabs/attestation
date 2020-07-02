package dk.alexandra.stormbird.cheque;

import com.sun.jmx.mbeanserver.NamedObject;
import java.security.spec.ECPoint;

public class Cheque {

  public int getAmount() {
    return amount;
  }

  public byte[] getRiddle() {
    return riddle;
  }

  private final int amount;
  private final byte[] riddle;

  public Cheque(int amount, byte[] riddle) {
    this.amount = amount;
    this.riddle = riddle;
  }
}
