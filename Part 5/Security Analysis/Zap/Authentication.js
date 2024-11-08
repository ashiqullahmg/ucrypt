/*
 * ZAP Authentication Script
 * This script is intended to be used along with httpsender/httpSender.js script to
 * handle an offline token refresh workflow.
 * This will automatically fetch the new access token for every unauthorized
 * request determined by the "Logged Out" or "Logged In" indicator that you may set
 * in Context/Authentication.
 * The httpSender.js will add the new access token to all requests in scope
 * made by ZAP (except the authentication ones) as an "Authorization: Bearer [access_token]" HTTP Header.
 * 2. Defines the 'authenticate' function to:
 *    - Extract endpoint and credentials from parameters.
 *    - Build and send an HTTP PUT request to the login endpoint.
 *    - Parse the JSON response to extract and store the access token.
 * 3. Helper functions:
 *    - 'getRequiredParamsNames': Returns required parameter names.
 *    - 'getOptionalParamsNames': Returns optional parameter names (empty).
 *    - 'getCredentialsParamsNames': Returns credential parameter names.
 */

var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

function authenticate(helper, paramsValues, credentials) {
  var login_endpoint = paramsValues.get("login_endpoint");
  var email = credentials.getParam("email");
  var password = credentials.getParam("password");

  // Build body
  var loginBody = JSON.stringify({
    email: email,
    password: password
  });

  // Build header
  var loginRequestURI = new URI(login_endpoint, false);
  var loginRequestMethod = HttpRequestHeader.PUT;
  var loginRequestMainHeader = new HttpRequestHeader(loginRequestMethod, loginRequestURI, HttpHeader.HTTP11);
  loginRequestMainHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/json");

  // Build message
  var loginMsg = helper.prepareMessage();
  loginMsg.setRequestBody(loginBody);
  loginMsg.setRequestHeader(loginRequestMainHeader);
  loginMsg.getRequestHeader().setContentLength(loginMsg.getRequestBody().length());

  // Make the request and receive the response
  helper.sendAndReceive(loginMsg, false);

  // Parse the JSON response and save the new access_token in a global var
  var json = JSON.parse(loginMsg.getResponseBody().toString());
    print("Response JSON: " + JSON.stringify(json, null, 2)); 
  var access_token = json["accessToken"];

  if (access_token) {
    ScriptVars.setGlobalVar("access_token", access_token);
  } else {
    print("Error getting access token");
  }

  return loginMsg;
}

function getRequiredParamsNames() {
  return ["login_endpoint"];
}

function getOptionalParamsNames() {
  return [];
}

function getCredentialsParamsNames() {
  return ["email", "password"];
}
