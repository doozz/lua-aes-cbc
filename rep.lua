local json_util = require "cjson.safe"
local aes = require "resty.aes"
local str = require "resty.string"
local ngx_encode_base64 = ngx.encode_base64

local function res_json(resp)
    local str = json_util.decode(resp)
    local res = {}
    res["code"] = ngx.var.statu_code
    res["data"] = str
    local data = json_util.encode(res)
    local aes_128_cbc_with_iv = assert(aes:new(ngx.var.encrty_code,
    nil, aes.cipher(128,"cbc"), {iv=ngx.var.iv_code}))
    local encrypted = aes_128_cbc_with_iv:encrypt(data)
    return ngx_encode_base64(encrypted)
    -- return data
end

if (ngx.var.exit)
then
return
end

local resp_body = string.sub(ngx.arg[1],1,10000) 
ngx.ctx.buffered = (ngx.ctx.buffered or "") .. resp_body
if ngx.arg[2] then
    ngx.arg[1] = res_json(ngx.ctx.buffered)
else
    ngx.arg[1] = nil
end

