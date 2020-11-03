local _M = {}

local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")
local oauth_utils = require("kong.plugins." .. plugin_name .. ".oauth_utils")
local parse_variables = require("kong.plugins." .. plugin_name .. ".parse_variables")

local ngx_log     = ngx.log
local ngx_ERR     = ngx.ERR


function _M:issuer(conf)

  local oauth_cred_id,
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
        unescape_uri = parse_variables:declare_common_vars(conf)

  local scope, authorize_url, access_token_url, userinfo_url = parse_variables:declare_provider_specific_vars(conf)

  local key, client_id, client_secret = parse_variables:declare_key_client_id_secret(oauth_cred_id, private_key_id, conf)

  if not (redirect_url ~= (cb_url .. "?uri=" .. uri)) then
    oauth_utils:redirect_to_auth(authorize_url, client_id, scope, cb_url, redirect_url, conf['oauth_provider'])
  end

  if uri_args["error"] then
    ngx_log(ngx_ERR, "received " .. uri_args["error"] .. " from " .. authorize_url)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local token, token_err = oauth_utils:request_access_token(access_token_url, uri_args["code"], client_id, client_secret, cb_url, ssl_verify)
  if not token then
    ngx_log(ngx_ERR, "got error during access token request: " .. token_err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local profile, profile_err = oauth_utils:request_profile(userinfo_url, token, ssl_verify, conf['oauth_provider'])
  if not profile then
    ngx_log(ngx_ERR, "got error during profile request: " .. profile_err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local claims = oauth_utils:generate_claims(profile, issuer, jwt_validity, conf['oauth_provider'])

  oauth_utils:redirect_with_cookie(
    claims,
    key,
    private_key_id,
    jwt_validity,
    secure_cookies,
    http_only_cookies,
    cookie_name,
    uri_args,
    jwt_at_payload,
    jwt_at_payload_http_code,
    jwt_at_payload_key,
    unescape_uri
  )

end

return _M
