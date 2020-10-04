package dk.alexandra.stormbird.issuer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

public class TestAttestation {
  public static final ECDomainParameters DOMAIN = new ECDomainParameters(Attestation.CURVE_PARAM.getCurve(), Attestation.CURVE_PARAM.getG(), Attestation.CURVE_PARAM.getN(), Attestation.CURVE_PARAM.getH());
  private static AsymmetricCipherKeyPair serverKeys, userKeys;
  private static String request;
  private static JSONObject record; // "Record" from the verifyResponse.json
  private static SecureRandom rand;

  @org.junit.BeforeClass
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    serverKeys = constructSecp256k1Keys(rand);
    userKeys = constructSecp256k1Keys(rand);
    request = Files.readString(Path.of("tests/verification_request.json"));
    JSONObject response = new JSONObject(Files.readString(Path.of("tests/verification_response.json")));
    record = response.getJSONObject("Record");
  }

  @Test
  public void testSunshine() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    long lifetime = 31536000000l; // one year
    Attestation att = new Attestation(serverKeys, new X500Name("CN=Stormbird"), lifetime);
    byte[] requestJson = request.getBytes(StandardCharsets.UTF_8);
    byte[] signature = SignatureUtil.signKeccak(requestJson, userKeys.getPrivate());
    System.out.println(new String(Base64.getEncoder().encode(signature)));
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(userKeys.getPublic());
    byte[] userPK = spki.getPublicKeyData().getEncoded();
    System.out.println(new String(Base64.getEncoder().encode(userPK)));
    List<byte[]> certs = att.constructAttestation(request, record.toString(), signature, userPK);
    JcaX509ContentVerifierProviderBuilder builder = new JcaX509ContentVerifierProviderBuilder();
    SubjectPublicKeyInfo issuerSpki =  SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(serverKeys.getPublic());
    ContentVerifierProvider verifier = builder.build(issuerSpki);
    PublicKey serverPK = new EC().generatePublic(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(serverKeys.getPublic()));
    System.out.println(ASN1Util.printDER(serverPK.getEncoded(), "PUBLIC KEY"));
    for (byte[] current : certs) {
      System.out.println(ASN1Util.printDER(current, "CERTIFICATE"));
      X509CertificateHolder currentCert = new X509CertificateHolder(current);
      Assert.assertTrue(currentCert.isValidOn(new Date(System.currentTimeMillis())));
      Assert.assertTrue(currentCert.isSignatureValid(verifier));
    }

    // TODO the code below does not work since only named ECParameters are supported in X509CertImpl
//    for (byte[] current : certs) {
//      X509Certificate cert = new X509CertImpl(current);
//      try {
//        cert.verify(serverPK, new BouncyCastleProvider());
//        cert.checkValidity();
//      } catch (CertificateExpiredException | CertificateNotYetValidException e) {
//        Assert.fail();
//      }
//    }

  }

  public static AsymmetricCipherKeyPair constructSecp256k1Keys(SecureRandom rand) {
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(DOMAIN, rand);
    generator.init(keygenParams);
    return generator.generateKeyPair();
  }
}