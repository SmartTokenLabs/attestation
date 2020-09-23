package dk.alexandra.stormbird.issuer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

public class TestParser {

  @Test
  public void testSunshine() throws Exception {
    String request = Files.readString(Path.of("tests/verification_request.json"));
    String response = Files.readString(Path.of("tests/verification_response.json"));
    Parser parser = new Parser(new JSONObject(request), new JSONObject(response));
    Map<String, X500Name> names = parser.getX500Names();
    Map<String, Extensions> extensions = parser.getExtensions();

    Assert.assertEquals(names.size(), 2);
    Assert.assertEquals(extensions.size(), 2);
    Assert.assertTrue(names.containsKey("National Change of Address"));
    Assert.assertTrue(names.containsKey("NZ Driver Licence"));
    Assert.assertTrue(extensions.containsKey("National Change of Address"));
    Assert.assertTrue(extensions.containsKey("NZ Driver Licence"));
    Set<String> expectedNameFields =
        new HashSet<String>(Arrays.asList(Parser.OID_COUNTRY_NAME, Parser.OID_GIVEN_NAME, Parser.OID_SUR_NAME, Parser.OID_STATE_OR_PROVINCE_NAME));
    for(X500Name name: names.values()) {
      Set<String> oids = Arrays.stream(name.getAttributeTypes()).map(c -> c.toString()).collect(Collectors.toSet());
      Assert.assertEquals(oids.size(), expectedNameFields.size());
      Assert.assertEquals(oids, expectedNameFields);
      Set<String> encs = Arrays.stream(name.getRDNs()).map(
          c -> c.getTypesAndValues()[0].getValue().toString()).collect(
          Collectors.toSet());
      Assert.assertEquals(encs.size(), 4);
      Assert.assertTrue(encs.contains("NZ"));
      Assert.assertTrue(encs.contains("JaneKone"));
      Assert.assertTrue(encs.contains("Doe"));
      Assert.assertTrue(encs.contains("Queensland"));
    }
    Set<String> expectedDLExtensions = new HashSet<>(Arrays.asList(Parser.OID_STREET_ADDRESS, Parser.OID_SUBURB, Parser.OID_POSTAL_CODE, Parser.OID_DATE_OF_BIRTH));
    Set<String> oids = Arrays.stream(extensions.get("NZ Driver Licence").getExtensionOIDs()).map(c -> c.toString()).collect(
          Collectors.toSet());
    Assert.assertEquals(expectedDLExtensions.size(), oids.size());
    Assert.assertEquals(expectedDLExtensions, oids);
    Set<String> encs = Arrays.stream(extensions.get("NZ Driver Licence").getExtensionOIDs()).map(c -> new String(extensions.get("NZ Driver Licence").getExtension(c).getExtnValue().getOctets())).collect(
        Collectors.toSet());
    Assert.assertEquals(encs.size(), 4);
    Assert.assertTrue(encs.contains("1973111100"));
    Assert.assertTrue(encs.contains("13 Markeri Street"));
    Assert.assertTrue(encs.contains("4218"));
    Assert.assertTrue(encs.contains("Mermaid Beach"));

    Set<String> expectedCAExtensions = new HashSet<>(Arrays.asList(Parser.OID_STREET_ADDRESS, Parser.OID_SUBURB, Parser.OID_POSTAL_CODE));
    Set<String> caOids = Arrays.stream(extensions.get("National Change of Address").getExtensionOIDs()).map(c -> c.toString()).collect(
        Collectors.toSet());
    Assert.assertEquals(expectedCAExtensions.size(), caOids.size());
    Assert.assertEquals(expectedCAExtensions, caOids);
    Set<String> caEncs = Arrays.stream(extensions.get("National Change of Address").getExtensionOIDs()).map(c -> new String(extensions.get("National Change of Address").getExtension(c).getExtnValue().getOctets())).collect(
        Collectors.toSet());
    Assert.assertEquals(caEncs.size(), 3);
    Assert.assertTrue(caEncs.contains("13 Markeri Street"));
    Assert.assertTrue(caEncs.contains("4218"));
    Assert.assertTrue(caEncs.contains("Mermaid Beach"));

  }
}
