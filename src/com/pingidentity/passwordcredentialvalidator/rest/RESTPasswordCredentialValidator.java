/**
 * *************************************************************************
 * Copyright (C) 2014 Ping Identity Corporation All rights reserved.
 *
 * The contents of this file are subject to the terms of the Ping Identity
 * Corporation SDK Developer Guide.
 *
 *************************************************************************
 */
package com.pingidentity.passwordcredentialvalidator.rest;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.*;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.util.log.AttributeMap;

import org.json.simple.*;
import org.json.simple.parser.*;

import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.PasswordValidationException;
import com.pingidentity.sdk.password.PasswordCredentialValidatorAuthnException;

/**
 * The RESTPasswordCredentialValidator class validates username and password credentials against a REST service.
 */
public class RESTPasswordCredentialValidator implements PasswordCredentialValidator {
	
	// initialize logger into PF
    private final Log logger = LogFactory.getLog(this.getClass());
    
    // instantiate and obtain config object
    private RESTPasswordCredentialValidatorConfiguration config = new RESTPasswordCredentialValidatorConfiguration();

	/**
	 * Validates the given username and password in the manner appropriate to the plugin implementation.
	 * 
	 * @param username
	 *            the given username/id
	 * @param password
	 *            the given password
	 * @return An AttributeMap with at least one entry representing the principal. The key of the entry does not matter,
	 *         so long as the map is not empty. If the map is empty or null, the username and password combination is
	 *         considered invalid.
	 * @throws PasswordValidationException
	 *             runtime exception when the validator cannot process the username and password combination due to
	 *             system failure such as data source off line, host name unreachable, etc.
	 */
    @Override
    public AttributeMap processPasswordCredential(String username, String password) throws PasswordValidationException {
    	logger.debug("processPasswordCredential :: BEGIN");
    	
        AttributeMap attrs = null;
        logger.debug("processPasswordCredential :: username: " + username);

        try {
            if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
            	
            	attrs = verifyCredentialsViaREST(username, password);
            	
            	if (attrs != null && attrs.size() > 0) {
                    logger.debug("processPasswordCredential :: authentication successful");
                } else {
                    logger.debug("processPasswordCredential :: authentication failed");
            	}

            }
        } catch (PasswordCredentialValidatorAuthnException ex) {
            logger.debug("processPasswordCredential :: Exception is: " + ex + ", with message: " + ex.getMessageKey());
            throw new PasswordCredentialValidatorAuthnException(false, ex.getMessageKey());
        } catch (Exception ex) {
            logger.debug("Exception is " + ex);
            throw new PasswordValidationException("processPasswordCredential :: other error validating username/password", ex);
        }

        logger.debug("processPasswordCredential :: END");
        return attrs;
    }
    
    /********************************************************[ Token Parsing ]*****/
    Map<String, String> tokenMapping = new HashMap<String, String>();
    Pattern tokenPattern = Pattern.compile("\\$\\{([^}]*)\\}");

    
    private String GetTokenValue(String token) {

        if (tokenMapping.containsKey(token)) {
            String value = tokenMapping.get(token).toString();
            return value != null ? value : "";
        } else {
            return token;
        }
    }

    private String ReplaceTokens(String template) {
        StringBuffer sb = new StringBuffer();
        Matcher myMatcher = tokenPattern.matcher(template);
        while (myMatcher.find()) {
            String field = myMatcher.group(1);
            myMatcher.appendReplacement(sb, "");
            sb.append(GetTokenValue(field));
        }
        myMatcher.appendTail(sb);
        return sb.toString();
    }

    private JSONObject replaceTokensInPOSTData(String body, String username, String password) {
    	
    	tokenMapping.put("username", username);
    	tokenMapping.put("password", password);
    	
    	// parse the username/password variables inside the body
    	try {
			return (JSONObject) new JSONParser().parse(ReplaceTokens(body));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
    }

    private String replaceTokensInUrl(String url, String username, String password) {
    	
    	tokenMapping.put("username", username);
    	tokenMapping.put("password", password);
    	
		return ReplaceTokens(url);
    }

    private AttributeMap verifyCredentialsViaREST(String username, String password) throws Exception {

		logger.debug("---[ Authenticating via REST ]------");
		logger.debug(" Email    : " + username);
		logger.debug(" Password : ********");

		URL restUrl = new URL(replaceTokensInUrl(config.restService, username, password));
		URLConnection urlConnection = restUrl.openConnection();
		
		if (config.httpHeaders.size() > 0) {
			for (Map<String, String> row : config.httpHeaders) {
				for (String k : row.keySet()) {
					urlConnection.addRequestProperty(k, row.get(k));
				}
			}
		}

		if (config.requestType.equals("GET")) {
			urlConnection.connect();
		} else { // POST
			urlConnection.setDoOutput(true);
			OutputStreamWriter outputStreamWriter = new OutputStreamWriter(urlConnection.getOutputStream(), "UTF-8");
			JSONObject postBody = replaceTokensInPOSTData(config.httpBody, username, password);
			postBody.writeJSONString(outputStreamWriter);
			outputStreamWriter.flush();
			outputStreamWriter.close();
		}

		if (urlConnection instanceof HttpURLConnection) {
			HttpURLConnection httpConnection = (HttpURLConnection) urlConnection;
			int responseCode = httpConnection.getResponseCode();

			logger.debug("-- Got HTTP Response code: " + responseCode);
			
			// response code or value

			if (Integer.toString(responseCode).equals(config.responseValue)) {
				logger.debug("Authentication Successful");
				
				// populate the extra attributes
			    String encoding = urlConnection.getContentEncoding();
			    InputStream is = urlConnection.getInputStream();
			    InputStreamReader streamReader = new InputStreamReader(is, encoding != null ? encoding : "UTF-8");
			    JSONObject responseBody = (JSONObject)new JSONParser().parse(streamReader);
				
				httpConnection.disconnect();

                AttributeMap attrs = new AttributeMap();
                attrs.put("username", username);
                
                JSONObject attributeObject = null;
                
                if (config.jsonResponseObject != null) {
                	attributeObject = (JSONObject)responseBody.get(config.jsonResponseObject);
                } else {
                	attributeObject = responseBody;
                }
                	
                for(Object id : attributeObject.keySet()) {
                	if (id != null) {
                		attrs.put(id.toString(), attributeObject.get(id).toString());
                	}
                }
                
                return attrs;
			} else {
				logger.debug("Authentication Failed");
				httpConnection.disconnect();
				return null;
			}
		} else {
			throw new Exception("Not a HTTP connection");
		}
	}
    
	/**
	 * The getSourceDescriptor method returns the configuration details.
	 */
	@Override
	public PluginDescriptor getPluginDescriptor() {
		return config.getPluginDescriptor(this);
	}

	/**
	 * The configure method sets the configuration details.
	 */
	@Override
	public void configure(Configuration configuration) {
		config.configure(configuration);
	}    
}