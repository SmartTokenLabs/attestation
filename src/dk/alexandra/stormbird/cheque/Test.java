package dk.alexandra.stormbird.cheque;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.ECFieldFp;
import javafx.scene.effect.Light.Spot;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;

public class Test {

  @org.junit.jupiter.api.Test
  public void testComputePoint() throws Exception{
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
    ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(),
        spec.getN());


  }
}
