local _M = {}

local json           = require("cjson").new()
local ngx_b64        = require("ngx.base64")
local openssl_pkey   = require("resty.openssl.pkey")

local os_getenv = os.getenv
local pairs     = pairs
local tostring  = tostring
local table_concat = table.concat

local ngx_header     = ngx.header
local ngx_say        = ngx.say
local ngx_exit       = ngx.exit
local ngx_log        = ngx.log
local ngx_ERR        = ngx.ERR
local ngx_decode_b64 = ngx.decode_base64

json.decode_array_with_array_mt(true)

local function return_error(code,message)
  local m=tostring(message)
  local r='{"error": "'.. m .. '"}\n'
  ngx.status = code
  ngx_header["Content-Type"]='application/json'
  ngx_say(r)
  ngx_exit(ngx.status)
end

local function load_private_keys(env_jwt_signer_private_keys)
  env_jwt_signer_private_keys = env_jwt_signer_private_keys or "OAUTH_JWT_SIGNER_PRIVATE_KEYS"
  local content = os_getenv(env_jwt_signer_private_keys)
  if content == nil or err then
    ngx_log(ngx_ERR, "Could not read " .. env_jwt_signer_private_keys .. " env var.")
    return nil, tostring(err)
  end
  local pkeys = json.decode(content)
  if not pkeys then
    ngx_log(ngx_ERR, "Could not get 'keys' object from " .. env_jwt_signer_private_keys .. " env var" )
    return nil, "Could not get 'keys' object from " .. env_jwt_signer_private_keys .. " env var"
  end
  local private_keys={}
  for k,v in pairs(pkeys) do
    private_keys[k]=ngx_b64.decode_base64url(v)
  end
  return private_keys
end

local function load_oauth_credentials(env_oauth_credentials)
  env_oauth_credentials = env_oauth_credentials or "OAUTH_CREDENTIALS"
  local content = os_getenv(env_oauth_credentials)
  if content == nil or err then
    ngx_log(ngx_ERR, "Could not read " .. env_oauth_credentials .. " env var.")
    return nil, tostring(err)
  end
  local oauth_creds = json.decode(content)
  if not oauth_creds then
    ngx_log(ngx_ERR, "Could not decode " .. env_oauth_credentials .. " env var" )
    return nil, "Could not decode " .. env_oauth_credentials .. " env var"
  end
  return oauth_creds
end

function _M:declare_common_vars(conf)
  local oauth_cred_id     = conf['oauth_cred_id']
  local private_key_id    = conf['private_key_id']

  local unescape_uri      = conf['unescape_uri']

  local uri_args          = ngx.req.get_uri_args()
  local uri               = uri_args['uri'] or ""
  if unescape_uri then
    uri = ngx.unescape_uri(uri)
  end
  local jwt_validity      = conf['jwt_validity']
  local cookie_name       = conf['cookie_name']
  local secure_cookies    = conf['secure_cookies']
  local http_only_cookies = conf['http_only_cookies']
  local issuer            = conf['issuer']
  local cb_uri            = conf['callback_uri']
  local ssl_verify        = conf['ssl_verify']
  local cb_scheme         = conf['callback_scheme'] or ngx.var.scheme
  local cb_server_name    = ngx.req.get_headers()["Host"]
  if conf['strip_port_from_host'] then
    cb_server_name = cb_server_name:match( "(.-):?%d*$" )
  end
  local cb_url            = cb_scheme .. "://" .. cb_server_name .. cb_uri
  local request_uri       = ngx.var.request_uri
  if unescape_uri then
    request_uri = ngx.unescape_uri(request_uri)
  end
  local redirect_url      = cb_scheme .. "://" .. cb_server_name .. request_uri

  local jwt_at_payload           = conf['jwt_at_payload']
  local jwt_at_payload_http_code = conf['jwt_at_payload_http_code']
  local jwt_at_payload_key       = conf['jwt_at_payload_key']

  return oauth_cred_id,
          private_key_id,
          uri_args,
          uri,
          jwt_validity,
          cookie_name,
          secure_cookies,
          http_only_cookies,
          issuer,
          cb_uri,
          ssl_verify,
          cb_scheme,
          cb_server_name,
          cb_url,
          redirect_url,
          jwt_at_payload,
          jwt_at_payload_http_code,
          jwt_at_payload_key,
          unescape_uri
end

function _M:declare_provider_specific_vars(conf)
  if (conf['oauth_provider'] == 'gluu') then
    local gluu_url = conf['gluu_url'] or nil
    if (not gluu_url) then
      return_error(500, "Provider is 'gluu' but 'gluu_url' is missing")
    end
    local scope            = conf['scopes'] and table_concat(conf['scopes'], " ") or "email profile openid"
    local authorize_url    = gluu_url .. '/oxauth/restv1/authorize'
    local access_token_url = gluu_url .. '/oxauth/restv1/token'
    local userinfo_url     = gluu_url .. '/oxauth/restv1/userinfo'
    return scope, authorize_url, access_token_url, userinfo_url
  elseif (conf['oauth_provider'] == 'gitlab') then
    local gitlab_url       = conf['gitlab_url'] or 'https://gitlab.com'
    local scope            = conf['scopes'] and table_concat(conf['scopes'], " ") or "email profile openid"
    local authorize_url    = gitlab_url .. '/oauth/authorize'
    local access_token_url = gitlab_url .. '/oauth/token'
    local userinfo_url     = gitlab_url .. '/oauth/userinfo'
    return scope, authorize_url, access_token_url, userinfo_url
  elseif (conf['oauth_provider'] == 'github') then
    local scope            = conf['scopes'] and table_concat(conf['scopes'], " ") or "user:read user:email"
    local authorize_url    = 'https://github.com/login/oauth/authorize'
    local access_token_url = 'https://github.com/login/oauth/access_token'
    local userinfo_url     = 'https://api.github.com/user'
    return scope, authorize_url, access_token_url, userinfo_url
  elseif (conf['oauth_provider'] == 'google') then
    local scope            = conf['scopes'] and table_concat(conf['scopes'], " ") or "email profile openid"
    local authorize_url    = 'https://accounts.google.com/o/oauth2/auth'
    local access_token_url = 'https://accounts.google.com/o/oauth2/token'
    local userinfo_url     = 'https://www.googleapis.com/oauth2/v2/userinfo'
    return scope, authorize_url, access_token_url, userinfo_url
  elseif (conf['oauth_provider'] == 'facebook') then
    local scope            = conf['scopes'] and table_concat(conf['scopes'], " ") or "email public_profile"
    local authorize_url    = 'https://www.facebook.com/v7.0/dialog/oauth'
    local access_token_url = 'https://graph.facebook.com/v7.0/oauth/access_token'
    local userinfo_url     = 'https://graph.facebook.com/v7.0/me'
    return scope, authorize_url, access_token_url, userinfo_url
  elseif (conf['oauth_provider'] == 'microsoft') then
    local scope            = conf['scopes'] and table_concat(conf['scopes'], " ") or "User.Read"
    local authorize_url    = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    local access_token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
    local userinfo_url     = 'https://graph.microsoft.com/v1.0/me'
    return scope, authorize_url, access_token_url, userinfo_url
  elseif (conf['oauth_provider'] == 'zoho') then
    local scope            = conf['scopes'] and table_concat(conf['scopes'], " ") or "Aaaserver.profile.read"
    local authorize_url    = 'https://accounts.zoho.com/oauth/v2/auth'
    local access_token_url = 'https://accounts.zoho.com/oauth/v2/token'
    local userinfo_url     = 'https://accounts.zoho.com/oauth/user/info'
    return scope, authorize_url, access_token_url, userinfo_url
  else
    return_error(500, "Provider " .. conf['oauth_provider'] .. " not supported yet")
  end
end

function _M:declare_key_client_id_secret(oauth_cred_id, private_key_id, conf)
  local key, client_id, client_secret = nil, nil, nil
  if oauth_cred_id then
    local oauth_creds  = load_oauth_credentials()
    if oauth_creds[oauth_cred_id] then
      client_id = oauth_creds[oauth_cred_id]['client_id'] and oauth_creds[oauth_cred_id]['client_id'] or nil
      client_secret = oauth_creds[oauth_cred_id]['client_secret'] and oauth_creds[oauth_cred_id]['client_secret'] or nil
    else
      return_error(500, ("OAUTH CREDENTIAL ID: " .. oauth_cred_id .. " not found"))
    end
  end
  client_id = client_id and client_id or conf['client_id']
  client_secret = client_secret and client_secret or conf['client_secret']
  if conf['private_keys'][private_key_id] ~= nil then
    key = ngx_decode_b64(conf['private_keys'][private_key_id])
  else
    local private_keys = load_private_keys()
    if private_keys and private_keys[private_key_id] then
      key = private_keys[private_key_id]
    else
      return_error(500, ("PRIVATE KEY ID: " .. private_key_id .. " not found at"))
    end
  end
  if ((not key) or (not client_id) or (not client_secret)) then
    return_error(500, ("Could not load key, client_id or client_secret"))
  end
  local pkey = openssl_pkey.new(key)
  return pkey, client_id, client_secret
end

return _M
