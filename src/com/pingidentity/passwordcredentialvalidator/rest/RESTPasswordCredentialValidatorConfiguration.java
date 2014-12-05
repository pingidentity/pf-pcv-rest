package com.pingidentity.passwordcredentialvalidator.rest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextAreaFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;

import org.sourceid.saml20.adapter.conf.Row;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;

/**
 * The RESTPasswordCredentialValidatorConfiguration class contains PingFederate web GUI configuration parameters for the RESTPasswordCredentialValidator.
 */
public class RESTPasswordCredentialValidatorConfiguration {

	// initialize configuration object
    protected Configuration configuration = null;

    // lets make it easy. Make a GET web service call 200 OK is good, otherwise bad
    private static final String REST_SERVICE_URL = "REST Web Service URL";
    private static final String REST_SERVICE_URL_DESC = "The URL for the REST web service. If reqd, use ${username} for username, ${password} for password.";

    // How to call (GET / POST)
    private static final String REST_CALL_METHOD = "REST Method";
    private static final String REST_CALL_METHOD_DESC = "The HTTP method to call the REST web service.";

    // Authorization / Headers?
    private static final String HTTP_HEADERS_TABLE = "HTTP Headers";
    private static final String HTTP_HEADERS_TABLE_DESC = "HTTP headers to send with the request.";

    // Header Name
    private static final String HTTP_HEADER_NAME = "HTTP Header Name";
    private static final String HTTP_HEADER_NAME_DESC = "";

    // Header Value
    private static final String HTTP_HEADER_VALUE = "HTTP Header Value";
    private static final String HTTP_HEADER_VALUE_DESC = "";

    // Body
    private static final String HTTP_BODY = "HTTP Body";
    private static final String HTTP_BODY_DESC = "The body of the HTTP call (for POST method). Use ${username} for username, ${password} for password.";

    // What response are we expecting (HTTP Response code? response value?)
    private static final String EXPECTED_RESPONSE_TYPE = "Success Response Type";
    private static final String EXPECTED_RESPONSE_TYPE_DESC = "What response method to check for a successful login.";

    // Value to compare
    private static final String EXPECTED_RESPONSE_VALUE = "Success Response Value";
    private static final String EXPECTED_RESPONSE_VALUE_DESC = "Value to check for a successful login (ie the HTTP response code value).";
    
    // JSON Object containing return attributes
    private static final String JSON_OBJECT_NAME = "Response JSON Object Name";
    private static final String JSON_OBJECT_NAME_DESC = "Response JSON object containing return attributes (blank for root of the JSON response).";

    
    private static final String[] validRESTMethods = new String[] { "GET", "POST"};
    private static final String[] validResponseTypes = new String[] { "HTTP Response Code" };
    
    
    protected String restService = null;
    protected String requestType = null;
    protected String httpBody = null;
    protected String responseType = null;
    protected String responseValue = null;
    protected String jsonResponseObject = null;
    protected List<Map<String,String>> httpHeaders = new ArrayList<Map<String, String>>();
    
	/**
	 * This method is called by the PingFederate server to push configuration values entered by the administrator via
	 * the dynamically rendered GUI configuration screen in the PingFederate administration console. Your implementation
	 * should use the {@link Configuration} parameter to configure its own internal state as needed. <br/>
	 * <br/>
	 * Each time the PingFederate server creates a new instance of your plugin implementation this method will be
	 * invoked with the proper configuration. All concurrency issues are handled in the server so you don't need to
	 * worry about them here. The server doesn't allow access to your plugin implementation instance until after
	 * creation and configuration is completed.
	 * 
	 * @param configuration
	 *            the Configuration object constructed from the values entered by the user via the GUI.
	 */    
    public void configure(Configuration configuration) {
        this.restService = configuration.getFieldValue(REST_SERVICE_URL);
        this.requestType = configuration.getFieldValue(REST_CALL_METHOD);
        this.httpBody = configuration.getFieldValue(HTTP_BODY);
        this.responseType = configuration.getFieldValue(EXPECTED_RESPONSE_TYPE);
        this.responseValue = configuration.getFieldValue(EXPECTED_RESPONSE_VALUE);
        this.jsonResponseObject = configuration.getFieldValue(JSON_OBJECT_NAME);
        
        for (Row row : configuration.getTable(HTTP_HEADERS_TABLE).getRows())
        {
        	Map<String,String> currentRow = new HashMap<String, String>();
            currentRow.put(row.getFieldValue(HTTP_HEADER_NAME), row.getFieldValue(HTTP_HEADER_VALUE));
            this.httpHeaders.add(currentRow);
        }
        
    }

	/**
	 * Returns the {@link PluginDescriptor} that describes this plugin to the PingFederate server. This includes how
	 * PingFederate will render the plugin in the administrative console, and metadata on how PingFederate will treat
	 * this plugin at runtime.
	 * 
	 * @return A {@link PluginDescriptor} that describes this plugin to the PingFederate server.
	 */    
    public PluginDescriptor getPluginDescriptor(RESTPasswordCredentialValidator rcv) {
    	RequiredFieldValidator requiredFieldValidator = new RequiredFieldValidator();
    	
    	GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
		guiDescriptor.setDescription("REST Service Password Credential Validator");
		
        TextFieldDescriptor serviceDescriptor = new TextFieldDescriptor(REST_SERVICE_URL, REST_SERVICE_URL_DESC);
        serviceDescriptor.addValidator(requiredFieldValidator);
        serviceDescriptor.setDefaultValue("https://services.company.com/login");
        guiDescriptor.addField(serviceDescriptor);

        SelectFieldDescriptor restMethodDescriptor = new SelectFieldDescriptor(REST_CALL_METHOD, REST_CALL_METHOD_DESC, validRESTMethods);
        restMethodDescriptor.addValidator(requiredFieldValidator);
        restMethodDescriptor.setDefaultValue("POST");
        guiDescriptor.addField(restMethodDescriptor);

        TableDescriptor headerTable = new TableDescriptor(HTTP_HEADERS_TABLE, HTTP_HEADERS_TABLE_DESC);
        guiDescriptor.addTable(headerTable);
        
        TextFieldDescriptor httpHeaderName = new TextFieldDescriptor(HTTP_HEADER_NAME, HTTP_HEADER_NAME_DESC);
        headerTable.addRowField(httpHeaderName);

        TextFieldDescriptor httpHeaderValue = new TextFieldDescriptor(HTTP_HEADER_VALUE, HTTP_HEADER_VALUE_DESC);
        headerTable.addRowField(httpHeaderValue);

        TextAreaFieldDescriptor httpBodyDescriptor = new TextAreaFieldDescriptor(HTTP_BODY, HTTP_BODY_DESC, 5, 75);
        httpBodyDescriptor.setDefaultValue("{ \"accountVerification\" : { \"id\" : 12345, \"email\" : \"${username}\", \"password\" : \"${password}\" } }");
        guiDescriptor.addField(httpBodyDescriptor);
        
        SelectFieldDescriptor responseTypeDescriptor = new SelectFieldDescriptor(EXPECTED_RESPONSE_TYPE, EXPECTED_RESPONSE_TYPE_DESC, validResponseTypes);
        responseTypeDescriptor.addValidator(requiredFieldValidator);
        responseTypeDescriptor.setDefaultValue("HTTP Response Code");
        guiDescriptor.addField(responseTypeDescriptor);

        TextFieldDescriptor responseValueDescriptor = new TextFieldDescriptor(EXPECTED_RESPONSE_VALUE, EXPECTED_RESPONSE_VALUE_DESC);
        responseValueDescriptor.addValidator(requiredFieldValidator);
        responseValueDescriptor.setDefaultValue("200");
        guiDescriptor.addField(responseValueDescriptor);

        TextFieldDescriptor jsonObjectDescriptor = new TextFieldDescriptor(JSON_OBJECT_NAME, JSON_OBJECT_NAME_DESC);
        guiDescriptor.addField(jsonObjectDescriptor);
        
        PluginDescriptor pluginDescriptor = new PluginDescriptor("REST Service Password Credential Validator", rcv, guiDescriptor);
		//pluginDescriptor.setAttributeContractSet(Collections.singleton(USERNAME));
        HashSet<String> attributes = new HashSet<String>();
        attributes.add("username");
        pluginDescriptor.setAttributeContractSet(attributes);
		pluginDescriptor.setSupportsExtendedContract(true);
    	
		return pluginDescriptor;
    }
    

	/**
	 * The buildName method returns the name and version from the information in META-INF/MANIFEST.MF, in order to name the jar within this package.
	 * 
	 * @return name of the plug-in
	 */
	private String buildName() {
		Package plugin = RESTPasswordCredentialValidator.class.getPackage();
		String title = plugin.getImplementationTitle(); // Implementation-Title
		String version = plugin.getImplementationVersion(); // Implementation-Version:
		String name = title + " " + version;
		return name;
	}     
}