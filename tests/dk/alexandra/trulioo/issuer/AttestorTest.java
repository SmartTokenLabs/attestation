package dk.alexandra.trulioo.issuer;


import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class AttestorTest {
  public static final ECDomainParameters DOMAIN = new ECDomainParameters(
      Attestor.CURVE_PARAM.getCurve(), Attestor.CURVE_PARAM.getG(),
    Attestor.CURVE_PARAM.getN(), Attestor.CURVE_PARAM.getH());
  private static AsymmetricCipherKeyPair serverKeys, userKeys;
  private static String request;
  private static JSONObject record; // "Record" from the verifyResponse.json
  private static SecureRandom rand;
  private static Attestor attestor;

  @BeforeAll
  public static void setupAttestor() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    long lifetime = 31536000000l; // one year
    serverKeys = new AsymmetricCipherKeyPair(
        ASN1Util.restoreBase64PublicKey(Files.readString(Path.of("tests/IssuerPublicKey.pem"))),
        ASN1Util.restoreBase64PrivateKey(Files.readString(Path.of("tests/IssuerPrivateKey.pem"))));
    attestor = new Attestor(serverKeys, new X500Name("CN=Stormbird"), lifetime);
    JSONObject response = new JSONObject(Files.readString(Path.of("tests/verification_response.json")));
    record = response.getJSONObject("Record");
  }

  @Test
  public void testSunshine() throws Exception {
    /* setting up user's key, to sign verifyRequest */
    userKeys = constructSecp256k1Keys(rand);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(userKeys.getPublic());
    { // just to print newly generated public key here:
      byte[] userPK = spki.getPublicKeyData().getEncoded();
      System.out.println(ASN1Util.printDER(userPK, "PUBLIC KEY"));
    }

    /* signing verifyRequest */
    request = Files.readString(Path.of("tests/verification_request.json"));
    Security.addProvider(new BouncyCastleProvider());
    byte[] signature = SignatureUtil
        .signSha256(request.getBytes(StandardCharsets.UTF_8), userKeys.getPrivate());

    /* obtaining resulting attestations */
    List<X509CertificateHolder> certs = attestor.constructAttestations(request, record, signature, userKeys.getPublic());

    JcaX509ContentVerifierProviderBuilder builder = new JcaX509ContentVerifierProviderBuilder();
    SubjectPublicKeyInfo issuerSpki =  SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(serverKeys.getPublic());
    ContentVerifierProvider verifier = builder.build(issuerSpki);
    for (X509CertificateHolder cert : certs) {
      System.out.println(
          ASN1Util.printDER(cert.getEncoded(), "CERTIFICATE"));
      // This is how to take a encoded certificate and convert it back to X509CertificateHolder
      // X509CertificateHolder currentCert = new X509CertificateHolder(cert.getEncoded);
      Assertions.assertTrue(cert.isValidOn(new Date(System.currentTimeMillis())));
      Assertions.assertTrue(cert.isSignatureValid(verifier));
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
