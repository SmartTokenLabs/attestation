package dk.alexandra.trulioo.issuer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.json.JSONArray;
import org.json.JSONObject;

public class Parser {
  public static final String OID_GIVEN_NAME = "2.5.4.42";
  public static final String OID_SUR_NAME = "2.5.4.4";
  public static final String OID_COUNTRY_NAME = "2.5.4.6";
  public static final String OID_SUBURB = "2.5.4.7";
  public static final String OID_STATE_OR_PROVINCE_NAME = "2.5.4.8";
  public static final String OID_STREET_ADDRESS = "2.5.4.9";
  public static final String OID_POSTAL_CODE = "2.5.4.17";
  public static final String OID_DATE_OF_BIRTH = "1.3.6.1.4.1.8876.2.1.6";

  public static final Set<String> X500_OIDS = new HashSet<>(Arrays.asList(
      OID_COUNTRY_NAME,OID_STATE_OR_PROVINCE_NAME,OID_GIVEN_NAME, OID_SUR_NAME));

  private final Map<String, Map<String, String>> matching;
  private final Map<String, String> global;

  public Parser(JSONObject request, JSONObject response) {
    matching = matching(request, response);
    global = globalValues(request, response);
  }

  public Map<String, X500Name> getX500Names() {
    Map<String, X500Name> res = new HashMap<>();
    for (String currentDatasourceName : matching.keySet()) {
      X500NameBuilder builder = new X500NameBuilder();
      Map<String, String> currentMap = matching.get(currentDatasourceName);
      currentMap.putAll(global);
      for (String oid : currentMap.keySet()) {
        if (X500_OIDS.contains(oid)) {
          builder.addRDN(new ASN1ObjectIdentifier(oid), currentMap.get(oid));
        }
      }
      res.put(currentDatasourceName, builder.build());
    }
    return res;
  }

  public Map<String, Extensions> getExtensions() {
    Map<String, Extensions> res = new HashMap<>();
    for (String currentDatasourceName : matching.keySet()) {
      List<Extension> extensionList = new ArrayList<>();
      Map<String, String> currentMap = matching.get(currentDatasourceName);
      currentMap.putAll(global);
      for (String oid : currentMap.keySet()) {
        if (!X500_OIDS.contains(oid)) {
          Extension extension = new Extension(new ASN1ObjectIdentifier(oid), true,
              new DEROctetString(currentMap.get(oid).getBytes(StandardCharsets.UTF_8)));
          extensionList.add(extension);
        }
      }
      res.put(currentDatasourceName, new Extensions(extensionList.toArray(new Extension[0])));
    }
    return res;
  }

  private Map<String, String> globalValues(JSONObject request, JSONObject verifyRecord) {
    Map<String, String> output = new HashMap<>();
    // TODO: this might be a security issue:
    // the country code relationship of verify request and response is not checked here as we roll out only in 1 country
    //if (request.getString("CountryCode").equals(response.getString("CountryCode"))) {
      output.put(OID_COUNTRY_NAME, request.getString("CountryCode"));
    //}
    return output;
  }

  private Map<String, Map<String, String>> matching(JSONObject request, JSONObject verifyRecord) {
    Map<String, Map<String, Object>> preprocessed = new HashMap<>();
    JSONObject datafields = request.getJSONObject("DataFields");

    JSONArray datasourceResults = verifyRecord.getJSONArray("DatasourceResults");

    for(Object o: datasourceResults) {
      JSONObject current = (JSONObject)o;
      String dataSourceName = current.getString("DatasourceName");
      if("International Watchlist".equals(dataSourceName)) {
        continue;
      }
      JSONArray fields = current.getJSONArray("DatasourceFields");
      for(Object value : fields) {
        JSONObject currentValue = (JSONObject)value;
        if("match".equals(currentValue.getString("Status"))) {
          String fieldName = currentValue.getString("FieldName");
          for(String key: datafields.keySet()) {
            JSONObject field = datafields.getJSONObject(key);
            if(field.has(fieldName)) {
              preprocessed.putIfAbsent(dataSourceName, new HashMap<String, Object>());
              Map<String, Object> dataSourceMap = preprocessed.get(dataSourceName);
              Object hit = field.get(fieldName);
              dataSourceMap.put(fieldName, hit);
            }
          }
        }
      }
    }
    Map<String, Map<String, String>> postProcessed = new HashMap<>();
    for(String key: preprocessed.keySet()) {
      postProcessed.put(key, postProcess(preprocessed.get(key)));
    }
    return postProcessed;
  }

  private Map<String, String> postProcess(Map<String, Object> input) {
    Map<String, String> output = new HashMap<>();
    if(input.get("FirstGivenName") != null) {
      output.put(OID_GIVEN_NAME, (String) input.get("FirstGivenName"));
    }
    if(input.get("FirstSurName") != null) {
      output.put(OID_SUR_NAME, (String) input.get("FirstSurName"));
    }
    if(input.get("Suburb") != null) {
      output.put(OID_SUBURB, (String) input.get("Suburb"));
    }
    if(input.get("StateProvinceCode") != null) {
      output.put(OID_STATE_OR_PROVINCE_NAME, (String) input.get("StateProvinceCode"));
    }
    if(input.get("StreetName") != null && input.get("BuildingNumber") != null) {
      String address = input.get("BuildingNumber")+ " " +input.get("StreetName");
      if(input.get("StreetType") != null) {
        address += " "+ input.get("StreetType");
      }
      // We ignore City
		  /*if(input.get("City") != null) {
			  address += " "+ input.get("City");
		  }*/
      output.put(OID_STREET_ADDRESS, address);
    }
    if(input.get("PostalCode") != null) {
      output.put(OID_POSTAL_CODE, (String) input.get("PostalCode"));
    }
    if(input.get("YearOfBirth") != null && input.get("MonthOfBirth") != null && input.get("DayOfBirth") != null) {
      String birthdate = ""+input.get("YearOfBirth")+input.get("MonthOfBirth")+input.get("DayOfBirth")+"00";
      output.put(OID_DATE_OF_BIRTH, birthdate);
    }
    return output;
  }
}