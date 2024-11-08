/*
*  HTTP Sender Script
 * This script is intended to be used along with authentication/Authentication.js script to
 * handle an offline token refresh workflow.
 *
 * authentication/Authentication.js will automatically fetch the new access token for every unauthorized
 * request determined by the "Logged Out" or "Logged In" indicator hat you may set
 * in Context/Authentication.
 *
 * httpsender/httpSender.js will add the new access token to all requests in scope
 * made by ZAP (except the authentication ones) as an "Authorization: Bearer [access_token]" HTTP Header.
 *
 */

var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

function sendingRequest(msg, initiator, helper) {
  // add Authorization header to all request in scope except the authorization request itself
  if (initiator !== HttpSender.AUTHENTICATION_INITIATOR && msg.isInScope()) {
    msg.getRequestHeader().setHeader("Authorization", "Bearer " + ScriptVars.getGlobalVar("access_token"));
  }
}

function responseReceived(msg, initiator, helper) {}
