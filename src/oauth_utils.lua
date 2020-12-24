local _M = {}

local json           = require("cjson").new()
local openssl_digest = require("resty.openssl.digest")
local openssl_pkey   = require("resty.openssl.pkey")
local http           = require("resty.http")

local tostring = tostring

local encode_base64  = ngx.encode_base64
local ngx_header     = ngx.header
local ngx_say        = ngx.say
local ngx_exit       = ngx.exit
local ngx_time       = ngx.time
local ngx_re_match   = ngx.re.match
local ngx_redirect   = ngx.redirect
local ngx_log        = ngx.log
local ngx_ERR        = ngx.ERR

json.decode_array_with_array_mt(true)

local function return_error(code,message)
  local m=tostring(message)
  local r='{"error": "'.. m .. '"}\n'
  ngx.status = code
  ngx_header["Content-Type"]='application/json'
  ngx_say(r)
  ngx_exit(ngx.status)
end

local function sign_jwt(claims, key, private_key_id, alg, typ)
  alg = alg or 'RS512'
  typ = typ or 'JWT'
  local headers={}
  headers['alg']=alg
  headers['typ']=typ
  headers['kid']=private_key_id
  local h=encode_base64(json.encode(headers)):gsub("==$", ""):gsub("=$", "")
  local c = encode_base64(json.encode(claims)):gsub("==$", ""):gsub("=$", "")
  local data = h .. '.' .. c

  local pkey = openssl_pkey.new(key)
  local digest = openssl_digest.new("sha512")
  digest:update(data)
  local signature, err = pkey:sign(digest)
  if err then
    return nil, err
  end
  return(data .. ".".. encode_base64(signature):gsub("+", "-"):gsub("/", "_"):gsub("==$", ""):gsub("=$", ""))
end

local function request_profile(userinfo_url, token, ssl_verify, request_timeout)
  request_timeout = request_timeout or 3000
  local request = http.new()
  request:set_timeout(request_timeout)
  local res, err = request:request_uri(userinfo_url, {
    headers = {
      ["Authorization"] = token,
      ["Accept"] = "application/json"
    },
    ssl_verify = ssl_verify,
  })
  if not res then
    return nil, "auth info request failed: " .. (err or "unknown reason")
  end
  if res.status ~= 200 then
    return nil, "received " .. res.status .. " from " .. userinfo_url
  end
  return json.decode(res.body)
end

local function request_profile_get(userinfo_url, token, id_token, ssl_verify, request_method, request_timeout)
  request_method  = request_method or "GET"
  request_timeout = request_timeout or 3000
  local request = http.new()
  request:set_timeout(request_timeout)
  local res, err = request:request_uri(userinfo_url .. "?" .. ngx.encode_args({
        authorization = id_token,
        access_token  = token
      }), {
    method = request_method,
    ssl_verify = ssl_verify,
  })
  if not res then
    return nil, "auth info request failed: " .. (err or "unknown reason")
  end
  if res.status ~= 200 then
    return nil, "received " .. res.status .. " from " .. userinfo_url
  end
  return json.decode(res.body)
end

local function request_profile_facebook(userinfo_url, token, id_token, ssl_verify, request_method, request_timeout)
  request_method  = request_method or "GET"
  request_timeout = request_timeout or 3000
  local request = http.new()
  request:set_timeout(request_timeout)
  local res, err = request:request_uri(userinfo_url .. "?" .. ngx.encode_args({
        authorization = id_token,
        access_token  = token,
        fields = 'id,first_name,last_name,middle_name,name,picture{url},short_name,email'
      }), {
    method = request_method,
    ssl_verify = ssl_verify,
  })
  if not res then
    return nil, "auth info request failed: " .. (err or "unknown reason")
  end
  if res.status ~= 200 then
    return nil, "received " .. res.status .. " from " .. userinfo_url
  end
  return json.decode(res.body)
end

local function generate_claims_google(profile, issuer, jwt_validity)
  local claims={}
  claims["sub"] = profile["email"]
  claims["iss"] = issuer
  claims["iat"] = ngx_time()
  claims["exp"] = ngx_time() + jwt_validity
  claims["email_verified"] = profile["verified_email"] or nil
  claims["user"] = profile["email"]:match("([^@]+)@.+") or nil
  claims["domain"] = profile["email"]:match("[^@]+@(.+)") or nil
  claims["picture"] = profile["picture"] or nil
  claims["name"] = profile["name"] or nil
  claims["family_name"] = profile["family_name"] or nil
  claims["given_name"] = profile["given_name"] or nil
  claims["provider"] = 'google'
  return claims
end

local function generate_claims_gluu(profile, issuer, jwt_validity)
  local claims = {}
  claims["sub"] = profile["email"]
  claims["iss"] = issuer
  claims["iat"] = ngx_time()
  claims["exp"] = ngx_time() + jwt_validity
  claims["email_verified"] = profile["email_verified"]
  claims["user"] = profile["email"]:match("([^@]+)@.+")
  claims["domain"] = profile["email"]:match("[^@]+@(.+)")
  claims["name"] = profile["name"]
  claims["family_name"] = profile["family_name"]
  claims["given_name"] = profile["given_name"]
  claims["roles"] = profile["roles"] and profile["roles"] or nil
  claims["provider"] = 'gluu'
  return claims
end

local function generate_claims_facebook(profile, issuer, jwt_validity)
  local claims = {}
  claims["sub"] = profile["email"] and profile["email"] or profile["id"]
  claims["iss"] = issuer
  claims["iat"] = ngx.time()
  claims["exp"] = ngx.time() + jwt_validity
  claims["user"] = profile["email"]:match("([^@]+)@.+")
  claims["domain"] = profile["email"]:match("[^@]+@(.+)")
  claims["name"] = profile["name"]
  claims["family_name"] = profile["last_name"]
  claims["given_name"] = profile["first_name"]
  claims["picture"] = profile["picture"]["data"]["url"]
  claims["short_name"] = profile["short_name"]
  claims["provider"] = 'facebook'
  return claims
end

local function generate_claims_github(profile, issuer, jwt_validity)
  local claims = {}
  if type(profile["email"]) == 'userdata' then
    claims["sub"] = profile["login"]
    claims["user"] = profile["login"]
  else
    claims["sub"] = profile["email"]
    claims["user"] = profile["email"]:match("([^@]+)@.+")
    claims["domain"] = profile["email"]:match("[^@]+@(.+)")
  end
  claims["iss"] = issuer
  claims["iat"] = ngx.time()
  claims["exp"] = ngx.time() + jwt_validity
  claims["name"] = profile["name"]
  claims["provider"] = 'github'
  return claims
end

local function generate_claims_gitlab(profile, issuer, jwt_validity)
  local claims = {}
  claims["sub"] = profile["email"]
  claims["iss"] = issuer
  claims["iat"] = ngx.time()
  claims["exp"] = ngx.time() + jwt_validity
  claims["email_verified"] = profile["email_verified"]
  claims["user"] = profile["email"]:match("([^@]+)@.+")
  claims["domain"] = profile["email"]:match("[^@]+@(.+)")
  claims["name"] = profile["name"]
  claims["nickname"] = profile["nickname"]
  claims["picture"] = profile["picture"]
  claims["profile"] = profile["profile"]
  claims["groups"] = profile["groups"] and profile["groups"] or nil
  claims["provider"] = 'gitlab'
  return claims
end

local function generate_claims_microsoft(profile, issuer, jwt_validity)
  local claims = {}
  claims["sub"] = profile["userPrincipalName"]
  claims["iss"] = issuer
  claims["iat"] = ngx_time()
  claims["exp"] = ngx_time() + jwt_validity
  claims["name"] = profile["displayName"]
  claims["user"] = profile["userPrincipalName"]:match("([^@]+)@.+")
  claims["domain"] = profile["userPrincipalName"]:match("[^@]+@(.+)")
  claims["given_name"] = profile["givenName"]
  claims["family_name"] = profile["surname"]
  claims["provider"] = 'microsoft'
  return claims
end

local function generate_claims_yandex(profile, issuer, jwt_validity)
  local claims = {}
  claims["sub"] = profile["login"]
  claims["iss"] = issuer
  claims["iat"] = ngx_time()
  claims["exp"] = ngx_time() + jwt_validity
  claims["name"] = profile["real_name"]
  claims["user"] = profile["login"]:match("([^@]+)@.+")
  claims["domain"] = profile["login"]:match("[^@]+@(.+)")
  claims["given_name"] = profile["first_name"]
  claims["family_name"] = profile["last_name"]
  claims["provider"] = 'yandex'
  return claims
end

local function generate_claims_zoho(profile, issuer, jwt_validity)
  local claims = {}
  claims["sub"] = profile["Email"]
  claims["iss"] = issuer
  claims["iat"] = ngx.time()
  claims["exp"] = ngx.time() + jwt_validity
  claims["name"] = profile["Display_Name"]
  claims["user"] = profile["Email"]:match("([^@]+)@.+")
  claims["domain"] = profile["Email"]:match("[^@]+@(.+)")
  claims["given_name"] = profile["First_Name"]
  claims["family_name"] = profile["Last_Name"]
  claims["provider"] = 'zoho'
  return claims
end

local function redirect_to_auth(authorize_url, client_id, scope, cb_url, redirect_url, code)
  return ngx.redirect(authorize_url .."?" .. ngx.encode_args({
    client_id     = client_id,
    scope         = scope,
    response_type = code,
    redirect_uri  = cb_url,
    state         = redirect_url
  }))
end

local function redirect_to_auth_github(authorize_url, client_id, scope, cb_url, redirect_url, code, allow_signup)
  return ngx.redirect(authorize_url .."?" .. ngx.encode_args({
    client_id     = client_id,
    scope         = scope,
    response_type = code,
    redirect_uri  = cb_url,
    state         = redirect_url,
    allow_signup  = allow_signup
  }))
end

function _M:request_access_token(access_token_url, code, client_id, client_secret, cb_url, ssl_verify, grant_type, request_method, request_content_type, request_timeout)
  grant_type = grant_type or "authorization_code"
  request_timeout = request_timeout or 3000
  request_method = request_method or "POST"
  request_content_type = request_content_type or "application/x-www-form-urlencoded"
  local request = http.new()
  request:set_timeout(request_timeout)
  local res, err = request:request_uri(access_token_url, {
    method = request_method,
    body = ngx.encode_args({
    code          = code,
    client_id     = client_id,
    client_secret = client_secret,
    redirect_uri  = cb_url,
    grant_type    = grant_type,
    }),
    headers = {
      ["Content-type"] = request_content_type,
      ["Accept"] = "application/json"
    },
    ssl_verify = ssl_verify,
  })
  if not res then
    return nil, (err or "auth token request failed: " .. (err or "unknown reason"))
  end
  if res.status ~= 200 then
    return nil, "received " .. res.status .. " from ".. access_token_url .. ": " .. res.body
  end
  return json.decode(res.body)
end

function _M:redirect_to_auth(authorize_url, client_id, scope, cb_url, redirect_url, provider, code, allow_signup)
  allow_signup = allow_signup or "false"
  code = code or "code"
  if (provider == 'github') then
    redirect_to_auth_github(authorize_url, client_id, scope, cb_url, redirect_url, code, allow_signup)
  else
    redirect_to_auth(authorize_url, client_id, scope, cb_url, redirect_url, code)
  end
end

function _M:redirect_with_cookie(claims, key, private_key_id, jwt_validity, secure_cookies, http_only_cookies, cookie_name, uri_args, jwt_at_payload, jwt_at_payload_http_code, jwt_at_payload_key, unescape_uri)
  local jwt = sign_jwt(claims, key, private_key_id)

  local expires      = ngx_time() + jwt_validity
  local cookie_tail  = ";version=1;path=/;Max-Age=" .. expires
  if secure_cookies then
    cookie_tail = cookie_tail .. ";secure"
  end
  if http_only_cookies then
    cookie_tail = cookie_tail .. ";httponly"
  end
  ngx_header["Set-Cookie"] = {
    cookie_name .. "=" .. jwt .. cookie_tail
  }
  local m, err = ngx_re_match(uri_args["state"], "uri=(?<uri>.+)")
  if m then
    local uri = m["uri"]
    if unescape_uri then
      uri = ngx.unescape_uri(m["uri"])
    end
    if jwt_at_payload then
      ngx.status = jwt_at_payload_http_code
      ngx_header["Content-Type"]='application/json'
      ngx_header["Location"]=uri
      ngx_say('{"' .. jwt_at_payload_key .. '": "'.. jwt .. '"}')
      ngx_exit(ngx.status)
    else
      return ngx_redirect(uri)
    end
  else
    return ngx_exit(ngx.BAD_REQUEST)
  end
end

function _M:request_profile(userinfo_url, token, ssl_verify, provider)
  local profile, err
  if ((provider == 'google') or (provider == 'github') or (provider == 'microsoft') or (provider == 'yandex')) then
    profile, err = request_profile(userinfo_url, "Bearer " .. token["access_token"], ssl_verify)
  elseif (provider == 'zoho') then
    profile, err = request_profile(userinfo_url, "Zoho-oauthtoken " .. token["access_token"], ssl_verify)
  elseif ((provider == 'gluu') or (provider == 'gitlab')) then
    profile, err = request_profile_get(userinfo_url, token["access_token"], token["id_token"], ssl_verify)
  elseif (provider == 'facebook') then
    profile, err = request_profile_facebook(userinfo_url, token["access_token"], token["id_token"], ssl_verify)
  else
    return_error(500, "Provider " .. provider .. " not supported yet")
  end
  return profile, err
end

function _M:generate_claims(profile, issuer, jwt_validity, provider)
  local claims
  if (provider == 'gluu') then
    claims = generate_claims_gluu(profile, issuer, jwt_validity)
  elseif (provider == 'google') then
    claims = generate_claims_google(profile, issuer, jwt_validity)
  elseif (provider == 'facebook') then
    claims = generate_claims_facebook(profile, issuer, jwt_validity)
  elseif (provider == 'github') then
    claims = generate_claims_github(profile, issuer, jwt_validity)
  elseif (provider == 'gitlab') then
    claims = generate_claims_gitlab(profile, issuer, jwt_validity)
  elseif (provider == 'microsoft') then
    claims = generate_claims_microsoft(profile, issuer, jwt_validity)
  elseif (provider == 'yandex') then
    claims = generate_claims_yandex(profile, issuer, jwt_validity)
  elseif (provider == 'zoho') then
    claims = generate_claims_zoho(profile, issuer, jwt_validity)
  else
    return_error(500, "Provider " .. provider .. " not supported yet")
  end
  return claims
end

return _M
