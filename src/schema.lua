local typedefs = require "kong.db.schema.typedefs"
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

return {
  name = plugin_name,
  fields = {
    {
      config = {
        type = "record",
        fields = {
          { oauth_provider = {
            type = "string",
            one_of = {
              "facebook",
              "github",
              "gitlab",
              "gluu",
              "google",
              "microsoft",
              "zoho",
            },
            default = "google",
            required = true
          } },
          { private_key_id = {
            type = "string",
            default = "12345678-1234-1234-1234-123456789ABC",
            required = true
          } },
          { oauth_cred_id = {
            type = "string",
            required = false
          } },
          { jwt_validity = {
            type = "number",
            default = 86400,
            required = true
          } },
          { cookie_name = {
            type = "string",
            default = "oauth_jwt",
            required = true
          } },
          { secure_cookies = {
            type = "boolean",
            default = true,
            required = true
          } },
          { http_only_cookies = {
            type = "boolean",
            default = true,
            required = true
          } },
          { issuer = {
            type = "string",
            default = "Kong",
            required = true
          } },
          { callback_uri = {
            type = "string",
            default = "/_oauth",
            required = false
          } },
          { ssl_verify = {
            type = "boolean",
            default = true,
            required = true
          } },
          { callback_scheme = {
            type = "string",
            required = false
          } },
          { scopes = {
            type = "array",
            elements = { type = "string" },
            required = false
          } },
          { gluu_url = {
            type = "string",
            required = false
          } },
          { gitlab_url = {
            type = "string",
            required = false
          } },
          { client_id = {
            type = "string",
            required = false
          } },
          { client_secret = {
            type = "string",
            required = false
          } },
          { private_keys = {
            type = "map",
            keys = { type = "string" },
            required = false,
            values = {
              type = "string",
              required = true,
            },
            default = {}
          } },
          { jwt_at_payload = {
            type = "boolean",
            default = false,
            required = true
          } },
          { jwt_at_payload_http_code = {
            type = "number",
            default = 200,
            required = true
          } },
          { jwt_at_payload_key = {
            type = "string",
            default = "access_token",
            required = true
          } },
          { unescape_uri = {
            type = "boolean",
            default = false,
            required = true
          } },
          { strip_port_from_host = {
            type = "boolean",
            default = false,
            required = true
          } },
        }, -- end of fields
      }, -- end of config
    },
  }, -- end of fields
}
