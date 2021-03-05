package com.acmeair.jmeter.functions;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;


import org.apache.jmeter.engine.util.CompoundVariable;
import org.apache.jmeter.functions.AbstractFunction;
import org.apache.jmeter.functions.InvalidVariableException;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.samplers.Sampler;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

public class GenerateJWTFunction extends AbstractFunction {

  private static String keyStoreLocation;
  private static String keyStoreType;
  private static String keyStorePassword;
  private static String keyStoreAlias;
  private static String jwtIssuer;
  private static String jwtGroup;
  private static String jwtSubject;
  private static String jwtAudience = null;

  private static final List<String> DESC = Arrays.asList("generate_jwt");
  private static final String KEY = "__generateJwt";

  private List<CompoundVariable> parameters = Collections.emptyList();

  private static String token = "";
  private static int count = 0;

  private static PrivateKey privateKey;

  static {
    if (System.getProperty("JWT.keystore.location") == null) {
      keyStoreLocation = "/keyfile/key.p12";
    } else {
      keyStoreLocation = System.getProperty("JWT.keystore.location");
    }
    if (System.getProperty("JWT.keystore.type") == null) {
      keyStoreType = "PKCS12";
    } else {
      keyStoreType = System.getProperty("JWT.keystore.type");
    }
    if (System.getProperty("JWT.keystore.password") == null) {
      keyStorePassword = "secret";
    } else {
      keyStorePassword = System.getProperty("JWT.keystore.password");
    }
    if (System.getProperty("JWT.keystore.alias") == null) {
      keyStoreAlias = "default";
    } else {
      keyStoreAlias = System.getProperty("JWT.keystore.alias");
    }
    if (System.getProperty("JWT.issuer") == null) {
      jwtIssuer = "http://acmeair-ms";
    } else {
      jwtIssuer = System.getProperty("JWT.issuer");
    }
    if (System.getProperty("JWT.group") == null) {
      jwtGroup= "user";
    } else {
      jwtGroup = System.getProperty("JWT.group");
    }
    if (System.getProperty("JWT.subject") == null) {
      jwtSubject = "subject";
    } else {
      jwtSubject = System.getProperty("JWT.subject");
    }
    if (System.getProperty("JWT.audience") == null) {
      jwtAudience = System.getProperty("JWT.audience");
    } 
       
    //Get the private key to generate JWTs and create the public JWK to send to the booking/customer service.
		try {
			FileInputStream is = new FileInputStream(keyStoreLocation);

			// For now use the p12 key generated for the service
			KeyStore keystore = KeyStore.getInstance(keyStoreType);
			keystore.load(is, keyStorePassword.toCharArray());
			privateKey = (PrivateKey) keystore.getKey(keyStoreAlias, keyStorePassword.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}

  }

  public String execute(SampleResult arg0, Sampler arg1) throws InvalidVariableException {


    if (count > 0 && token !="") {
      count = (count + 1) % 50;
      return token;
    }
    count = (count + 1) % 10;


    try {
      JwtClaims claims = new JwtClaims();
		  claims.setIssuer(jwtIssuer);  

		  claims.setExpirationTimeMinutesInTheFuture(15); 
		  claims.setGeneratedJwtId(); 
		  claims.setIssuedAtToNow(); 
		  claims.setSubject(jwtSubject); 
      claims.setClaim("upn", jwtSubject); 
		  List<String> groups = Arrays.asList(jwtGroup);
      claims.setStringListClaim("groups", groups);
      
      if (jwtAudience != null) {
        claims.setAudience(jwtAudience);
      }
		  
		  JsonWebSignature jws = new JsonWebSignature();
		  jws.setPayload(claims.toJson());
		  jws.setKey(privateKey);      
		  jws.setAlgorithmHeaderValue("RS256");
      jws.setHeader("typ", "JWT");
		
      token = jws.getCompactSerialization();
    } catch (Exception exception) {
      exception.printStackTrace(); 
    }    

    return token;
  }

  @Override
  public String getReferenceKey() {
    return KEY;
  }

  @Override
  public void setParameters(Collection<CompoundVariable> arg0) throws InvalidVariableException {
    parameters = new ArrayList<CompoundVariable>(arg0);
  }

  public List<String> getArgumentDesc() {
    return DESC;
  }
}
