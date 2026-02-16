// KubeDash authentication script for ZAP (HttpSender).
// Logs in with admin/admin, handles Flask CSRF token, and adds session cookie to all requests.
// Enable this script in the Scripts tree (right-click -> enable).

var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var URI = Java.type("org.apache.commons.httpclient.URI");

var KUBEDASH_BASE = "https://host.docker.internal:5000";
var LOGIN_USER = "admin";
var LOGIN_PASS = "admin";

function sendingRequest(msg, initiator, helper) {
  var url = msg.getRequestHeader().getURI().toString();
  if (!url.contains("host.docker.internal:5000")) {
    return;
  }
  var path = msg.getRequestHeader().getURI().getPath();
  if (path === null || path === "") path = "/";
  // Don't add cookie to login page GET or login POST
  if (path.equals("/") && (msg.getRequestHeader().getMethod().equals("GET") || msg.getRequestHeader().getMethod().equals("POST"))) {
    return;
  }

  var sessionCookie = org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar("kubedash_session");
  if (sessionCookie === null || sessionCookie === "") {
    doLogin(helper);
    sessionCookie = org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar("kubedash_session");
  }
  if (sessionCookie !== null && sessionCookie !== "") {
    var header = msg.getRequestHeader();
    header.setHeader("Cookie", "session=" + sessionCookie);
    msg.setRequestHeader(header);
  }
}

function doLogin(helper) {
  try {
    // 1. GET login page to obtain CSRF token
    var getMsg = new HttpMessage(new URI(KUBEDASH_BASE + "/", false));
    getMsg.getRequestHeader().setMethod(HttpRequestHeader.GET);
    helper.getHttpSender().sendAndReceive(getMsg, true);
    var body = getMsg.getResponseBody().toString();
    var csrfMatch = /name="csrf_token"\s+value="([^"]+)"/.exec(body);
    var csrfToken = (csrfMatch && csrfMatch[1]) ? csrfMatch[1] : "";
    // 2. POST login with username, password, csrf_token
    var postMsg = new HttpMessage(new URI(KUBEDASH_BASE + "/", false));
    postMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
    postMsg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
    var formBody = "username=" + encodeURIComponent(LOGIN_USER) + "&password=" + encodeURIComponent(LOGIN_PASS) + "&csrf_token=" + encodeURIComponent(csrfToken);
    postMsg.getRequestBody().setBody(formBody);
    postMsg.getRequestHeader().setHeader("Content-Length", String(postMsg.getRequestBody().length()));
    helper.getHttpSender().sendAndReceive(postMsg, true);
    // 3. Extract session cookie from POST response (Flask sends Set-Cookie: session=...)
    var setCookieStr = postMsg.getResponseHeader().getHeader("Set-Cookie");
    if (setCookieStr !== null && setCookieStr.indexOf("session=") !== -1) {
      var sessionVal = setCookieStr.replace(/^.*?\bsession=([^;]+).*$/, "$1").trim();
      if (sessionVal.length > 0) {
        org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar("kubedash_session", sessionVal);
      }
    }
  } catch (e) {
    print("KubeDash login script error: " + e.message);
  }
}

function responseReceived(msg, initiator, helper) {
  // Optional: on 401/302 to login, clear session to force re-login
  var url = msg.getRequestHeader().getURI().toString();
  if (!url.contains("host.docker.internal:5000")) return;
  var code = msg.getResponseHeader().getStatusCode();
  if (code === 401 || code === 302) {
    var loc = msg.getResponseHeader().getHeader("Location");
    if (loc !== null && loc.indexOf("login") !== -1) {
      org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar("kubedash_session", "");
    }
  }
}
