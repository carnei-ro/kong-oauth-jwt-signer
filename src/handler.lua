local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")
local access = require("kong.plugins." .. plugin_name .. ".oauth")

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.4.0-0",
}

function plugin:access(plugin_conf)
  access:issuer(plugin_conf) 
end

return plugin
