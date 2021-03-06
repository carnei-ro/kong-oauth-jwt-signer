# Kong OAuth JWT Signer

:warning: **Deprecated** :warning:

**Consider using https://github.com/carnei-ro/kong-plugin-oauth-jwt and https://github.com/carnei-ro/kong-plugin-oauth-jwt-signer**

OpenID Connect for "facebook", "github", "gitlab", "gluu", "google", "microsoft", "yandex" or "zoho".

## Use

Use with https://github.com/carnei-ro/kong-oauth-jwt-plugin  
Based on: https://github.com/cloudflare/nginx-google-oauth  
Plugin priority: 1000.  

**Requires Kong >= 2.1.0**

summary: generate JWT when openid flow is valid  


## Default values

```yaml
---
plugins:
- name: kong-oauth-jwt-signer
  config:
    oauth_provider: <empty> #REQUIRED (one of "facebook", "github", "gitlab", "gluu", "google", "microsoft", "zoho")
    oauth_cred_id: <empty> # id of client_id/client_secret from env var OAUTH_CREDENTIALS
    client_id: <empty> # or env var OAUTH_CREDENTIALS and oauth_cred_id configured
    client_secret: <empty> # or env var OAUTH_CREDENTIALS and oauth_cred_id configured
    private_keys: <empty> # (Map) private_keys or env var OAUTH_JWT_SIGNER_PRIVATE_KEYS
    # private_keys:
    #   12345678-1234-1234-1234-123456789ABC: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBMzlJN0J3ZGU3c1d4bEZnRnRJYVViTDVBUjY2WWJ0MmJmazFqREFDYjd4b25mam54CkpuZ2V3QUp2bU1sZmMwbVdKMFZZdU1SZ2pRMVBMbFFDai9KN1NZR1UydnNtS0I3VjIyVjU4Yjd6Z1BCVGtNNDEKVmMrTmZLNjN3RlVHWG1EK3c3QUkxYjl0V2c4TkV5N1JEcmltZldmUnhLNGlUSGZrSnpMYXJ6c3MzRHVzUzRNbQo0SVVyM3NmVzQxVWVYRkRNbm53NUVkS2x3b3dZRU90WmlySW1ZU1QrZDE5QWFlaDVOMU94YldoVWxqci9NYnFXCjV5VldkT2hGamRDSngyUGVoMXVPSVFJUnI1dFNEb2tpM2dBS1RWRnpyV3ZoZE51SGw1NTdKV2FTVnJxano5TGsKdFRFMjd5SlJYbWxmZitQUm9FYXJnRmNLNUZ4c3QxZUp0ZGEyT1FJREFRQUJBb0lCQVFDUVo0Zno2ZnFDM1FQTQpiTm9KZGdiTy9oUms2eTJuNGN5UHVZZ2MxMHZFQVVEWHZMUnNtSFZtZG12ZnpKU0x3ajloU09tTUZBOGpFaUl6CkJycThlcnEyV3lkWi9VM0o5dE1OZ1RRakY0cnRkcUREdlhkRnpPcEJOa3lSaDRuYlhJTWlhREhiRG0yVC9ELzQKVDIxTUxUQWxtdFVKS3p3dnorNWdwL3ZWc0wwcHZSVXV2ODE1bTRnUVJFN2laeEFPVGJIRk90WmVpalhHNnUrYgpOck5XQ2xoSkc5NWlTakp5TllCRnFrNGcxMjRrMG8reUVob2xjRlcrdWRJNG9PdWxPMVFiUlA5V3c5c0laQUtQCkFhYlZZbXlXZUx6MU5nTHhCYlpiYkRlSVVkTnNMbkhHRHVvMXBTZHZJME9CbUU0dFc4ZGNpeTA0SC9pU2hhUHcKR2Jib2hZb3hBb0dCQVBtcUhtL3lySTYxUG5uTjFlVkpiQXphWlZHckJGa1EwMGNQMXYrQTg5bFBRc25FKy90RAp6d1Z3WVU2b1RITEpUMlBhVCtURXQ4YUhhd1hPbUtrdUhpWDA5Q1dFNElkaXE2YUd6RWgvUEdlTllBRWI4ME9zCi9CZjBuQXRySWZyMmlUUmZBczZFOTZKV1U2L1Y1OXF5TDJMTHg1Sm5KWFNTeVU0NjNBVU5zb3pGQW9HQkFPV0EKT2k1Rmt6SVhOU0NTVWx6Z3A4R1ZNQ1cyTFJSNHprenJhak5NR0k4SHYxOGt3SytLaE10cmxPL09xK3JWQ1ByVgptVURROW1qZ1RKdWg2NExRZ2RiczNOeHpjelczN2hpZ0NHenZsMG1BZW4vVmRuWEVTTndiZWpNYmRyck9ha0FmClJnTnoyZEVkaDBhR0VTK2VtNG5yOTE3NGpaU0pJUU9uajl4dXhFTGxBb0dBVTVtVWNaWUlGQTA2cTF5eWFBR3EKN2E3ZnlIWUVrYkpobk9ULzhEU0U4dHBvbWRtZEt1anMxSHhxQ1FXdis2dlBLcmQ2a3pjUDlxbDN1ODBQTDI5aQo1d0RjRkFnbml3NE9Qa2ZhOWRldEtWdWNyeUpsMWQ2QjE1K3Y5TjdkMVFSaXN5ZXhiK2YwWithU1JVblNSbGZ1CktCM21hTzZqQ3lMdng0Tk1FMkVmemFVQ2dZQkhyQ0wvWG1VWXlKeWozbTV3YVF5YTdTK0xKM2l1b3dleWgvYXoKckhraStnVnUvamhhMmdTY3pxMUZzeUtIaFI1M3o0czc3Y1oyZkU0UWNLSHZTWlN5L1dnQVJPSGZEZUVDdWIvSAozWTgrdWl3SGppK2ZtYnd6V1RWeGpvc216ZDNxeHBtRDdJTkN4bGovMGxDOXNXZmJ5K0NHUFZOaDV1MXppYm5vCjJvTGFiUUtCZ1FDWnhRMXI0eXhYQURGbkh2MWhaOUlVNWZpbHl6TllISzR0eUV4ajdEcmlSM2p6bWUyVkVteXEKT0lXNEJCeE8wOGY1V3dpSFpITWdBZ1Q5WHFNd1pmaHRvQTcxNzIwbnVYZDZDMjF0U016VFZHdzQwN0E5SE9xNwpCVklGNWdUdUh4dThoRnFwS1pHTzJadkpjUkwzQUdlaUtob1pBQkJpNnBzenloYTdhNWJuYnc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
    gluu_url: <empty> #REQUIRED when oauth_provider is 'gluu'
    gitlab_url: <empty> #If null and oauth_provider is 'gitlab' will use https://gitlab.com as base url
    jwt_validity: 86400
    cookie_name: oauth_jwt
    secure_cookies: true
    http_only_cookies: true
    issuer: Kong
    callback_uri: /_oauth
    callback_scheme: null
    private_key_id: 12345678-1234-1234-1234-123456789ABC
    ssl_verify: true
    scopes: # (List) Auto complete depends on provider
    # scopes:
    # - email
    # - profile
    # - openid
    jwt_at_payload: false
    jwt_at_payload_http_code: 200
    jwt_at_payload_key: access_token
    unescape_uri: false
    strip_port_from_host: false
```

## Requirements

Edit `kong.conf` to configure lua to be able to validate SSL certificates:  

```conf
lua_ssl_trusted_certificate=/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
lua_ssl_verify_depth=3
```

(in Alpine, should install `ca-certificates` and use `/etc/ssl/certs/ca-certificates.crt`)

Create a `main.conf` to be loaded with Kong

```conf
env OAUTH_JWT_SIGNER_PRIVATE_KEYS;
env OAUTH_CREDENTIALS;
```

Edit `kong.conf` to permit expose environment variables `OAUTH_JWT_SIGNER_PRIVATE_KEYS` and `OAUTH_CREDENTIALS` to kong:
```conf
nginx_main_include=/path/to/main.conf
```

Generate a key pair to use in the JWT. (The `public` goes to the `kong-oauth-jwt-plugin` plugin.)  
```bash
openssl genrsa -out private.pem 2048 # generates the private
openssl rsa -in private.pem -outform PEM -pubout -out public.pem  # generates the public
```

Create the environment variable `OAUTH_CREDENTIALS` as JSON.
Format:  
```json
{
  "<oauth_cred_id>": {
    "client_id": "<value>",
    "client_secret": "<value>",
  }
}
```

Create the environment variable `OAUTH_JWT_SIGNER_PRIVATE_KEYS` as JSON.  
Format:  
- key = `kid` of the JWT 
- value = private key for the JWT in base64.  

To generates the base64 do:
```bash
cat private.pem | base64 | paste -s -d ""
```

Example:
`OAUTH_JWT_SIGNER_PRIVATE_KEYS`
```json
{
  "12345678-1234-1234-1234-123456789ABC":"LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBMzlJN0J3ZGU3c1d4bEZnRnRJYVViTDVBUjY2WWJ0MmJmazFqREFDYjd4b25mam54CkpuZ2V3QUp2bU1sZmMwbVdKMFZZdU1SZ2pRMVBMbFFDai9KN1NZR1UydnNtS0I3VjIyVjU4Yjd6Z1BCVGtNNDEKVmMrTmZLNjN3RlVHWG1EK3c3QUkxYjl0V2c4TkV5N1JEcmltZldmUnhLNGlUSGZrSnpMYXJ6c3MzRHVzUzRNbQo0SVVyM3NmVzQxVWVYRkRNbm53NUVkS2x3b3dZRU90WmlySW1ZU1QrZDE5QWFlaDVOMU94YldoVWxqci9NYnFXCjV5VldkT2hGamRDSngyUGVoMXVPSVFJUnI1dFNEb2tpM2dBS1RWRnpyV3ZoZE51SGw1NTdKV2FTVnJxano5TGsKdFRFMjd5SlJYbWxmZitQUm9FYXJnRmNLNUZ4c3QxZUp0ZGEyT1FJREFRQUJBb0lCQVFDUVo0Zno2ZnFDM1FQTQpiTm9KZGdiTy9oUms2eTJuNGN5UHVZZ2MxMHZFQVVEWHZMUnNtSFZtZG12ZnpKU0x3ajloU09tTUZBOGpFaUl6CkJycThlcnEyV3lkWi9VM0o5dE1OZ1RRakY0cnRkcUREdlhkRnpPcEJOa3lSaDRuYlhJTWlhREhiRG0yVC9ELzQKVDIxTUxUQWxtdFVKS3p3dnorNWdwL3ZWc0wwcHZSVXV2ODE1bTRnUVJFN2laeEFPVGJIRk90WmVpalhHNnUrYgpOck5XQ2xoSkc5NWlTakp5TllCRnFrNGcxMjRrMG8reUVob2xjRlcrdWRJNG9PdWxPMVFiUlA5V3c5c0laQUtQCkFhYlZZbXlXZUx6MU5nTHhCYlpiYkRlSVVkTnNMbkhHRHVvMXBTZHZJME9CbUU0dFc4ZGNpeTA0SC9pU2hhUHcKR2Jib2hZb3hBb0dCQVBtcUhtL3lySTYxUG5uTjFlVkpiQXphWlZHckJGa1EwMGNQMXYrQTg5bFBRc25FKy90RAp6d1Z3WVU2b1RITEpUMlBhVCtURXQ4YUhhd1hPbUtrdUhpWDA5Q1dFNElkaXE2YUd6RWgvUEdlTllBRWI4ME9zCi9CZjBuQXRySWZyMmlUUmZBczZFOTZKV1U2L1Y1OXF5TDJMTHg1Sm5KWFNTeVU0NjNBVU5zb3pGQW9HQkFPV0EKT2k1Rmt6SVhOU0NTVWx6Z3A4R1ZNQ1cyTFJSNHprenJhak5NR0k4SHYxOGt3SytLaE10cmxPL09xK3JWQ1ByVgptVURROW1qZ1RKdWg2NExRZ2RiczNOeHpjelczN2hpZ0NHenZsMG1BZW4vVmRuWEVTTndiZWpNYmRyck9ha0FmClJnTnoyZEVkaDBhR0VTK2VtNG5yOTE3NGpaU0pJUU9uajl4dXhFTGxBb0dBVTVtVWNaWUlGQTA2cTF5eWFBR3EKN2E3ZnlIWUVrYkpobk9ULzhEU0U4dHBvbWRtZEt1anMxSHhxQ1FXdis2dlBLcmQ2a3pjUDlxbDN1ODBQTDI5aQo1d0RjRkFnbml3NE9Qa2ZhOWRldEtWdWNyeUpsMWQ2QjE1K3Y5TjdkMVFSaXN5ZXhiK2YwWithU1JVblNSbGZ1CktCM21hTzZqQ3lMdng0Tk1FMkVmemFVQ2dZQkhyQ0wvWG1VWXlKeWozbTV3YVF5YTdTK0xKM2l1b3dleWgvYXoKckhraStnVnUvamhhMmdTY3pxMUZzeUtIaFI1M3o0czc3Y1oyZkU0UWNLSHZTWlN5L1dnQVJPSGZEZUVDdWIvSAozWTgrdWl3SGppK2ZtYnd6V1RWeGpvc216ZDNxeHBtRDdJTkN4bGovMGxDOXNXZmJ5K0NHUFZOaDV1MXppYm5vCjJvTGFiUUtCZ1FDWnhRMXI0eXhYQURGbkh2MWhaOUlVNWZpbHl6TllISzR0eUV4ajdEcmlSM2p6bWUyVkVteXEKT0lXNEJCeE8wOGY1V3dpSFpITWdBZ1Q5WHFNd1pmaHRvQTcxNzIwbnVYZDZDMjF0U016VFZHdzQwN0E5SE9xNwpCVklGNWdUdUh4dThoRnFwS1pHTzJadkpjUkwzQUdlaUtob1pBQkJpNnBzenloYTdhNWJuYnc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="
}
```
