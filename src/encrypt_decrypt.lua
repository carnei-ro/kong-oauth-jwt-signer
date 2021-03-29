local string_gsub   = string.gsub
local string_char   = string.char
local string_lower  = string.lower
local string_format = string.format
local string_byte   = string.byte
local tonumber      = tonumber
local ngx_log       = ngx.log
local ngx_ERR       = ngx.ERR


local _M = {}

local function hex2ascii(s)
  local r = string_gsub(s,"(.)(.)",function (x,y) local c = (x..y) return string_char(tonumber(c, 16)) end)
  return r
end

local function bin2hex(s)
  local s = string_gsub(s,"(.)",function (x) return string_lower(string_format("%02X",string_byte(x))) end)
  return s
end

function _M:encrypt(pkey, plain_text)
  local s, err = pkey:encrypt(plain_text)
  if err then
    ngx_log(ngx_ERR, err)
    ngx.exit(500)
  end

  local hex_s = bin2hex(s)
  return hex_s, nil
end

function _M:decrypt(pkey, encrypted_text)
  local decrypted, err = pkey:decrypt(hex2ascii(encrypted_text))
  if err then
    ngx_log(ngx_ERR, err)
    ngx.exit(500)
  end

  return decrypted, nil
end

return _M
