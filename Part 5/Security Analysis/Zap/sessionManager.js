/*
 * Session Management script for OWASP Juice Shop
 * 
 * For Authentication select:
 *      Authentication method:        JSON-based authentication
 *      Login FORM target URL:        http://localhost:3000/rest/user/login
 *      URL to GET Login Page:        http://localhost:3000/
 *      Login Request POST data:      {"email":"test@test.com","password":"test1"}
 *      Username Parameter:           email
 *      Password Parameter:           password
 *      Logged out regex:             \Q{"user":{}}\E
 * 
 * Obviously update with any local changes as necessary.
 */

var COOKIE_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.cookie;
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');

function extractWebSession(sessionWrapper) {
    // parse the authentication response
    var json = JSON.parse(sessionWrapper.getHttpMessage().getResponseBody().toString());
    var accessToken = json.accessToken;
    // save the authentication token
    sessionWrapper.getSession().setValue("accessToken", accessToken);
    ScriptVars.setGlobalVar("juiceshop.accessToken", accessToken);
}
        
function clearWebSessionIdentifiers(sessionWrapper) {
    var headers = sessionWrapper.getHttpMessage().getRequestHeader();
    headers.setHeader("Authorization", null);
    ScriptVars.setGlobalVar("juiceshop.accessToken", null);
}
        
function processMessageToMatchSession(sessionWrapper) {
    var accessToken = sessionWrapper.getSession().getValue("accessToken");
    if (accessToken === null) {
        print('JS mgmt script: no accessToken');
        return;
    }
    // add the saved authentication token as an Authorization header for each request
    var msg = sessionWrapper.getHttpMessage();
    msg.getRequestHeader().setHeader("Authorization", "Bearer " + accessToken);

    var cookie = new HtmlParameter(COOKIE_TYPE, "accessToken", accessToken);
    var cookies = msg.getRequestHeader().getCookieParams();
    cookies.add(cookie);
    msg.getRequestHeader().setCookieParams(cookies);
}

function getRequiredParamsNames() {
    return [];
}

function getOptionalParamsNames() {
    return [];
}
