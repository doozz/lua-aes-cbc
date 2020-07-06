local aes = require "resty.aes"
local str = require "resty.string"
-- local math = require "resty.math"
local resty_random = require "resty.random"
local cjson = require "cjson.safe"
local ngx_decode_base64 = ngx.decode_base64
local md5 = ngx.md5
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local request_method = ngx.var.request_method
local request_uri = ngx.var.request_uri
local headers = ngx.req.get_headers()
local os = headers["x-os"]
local version = headers["x-v"]
local iv = headers["x-tag"]

--  白名单
local function redkey(key)
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(100) -- 100ms

    local ok, err = red:connect("127.0.0.1", 6379)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect to redis: ", err)
        return nil
    end

    -- if ngx.var.redauth then
    --     local ok, err = red:auth(ngx.var.redauth)
    --     if not ok then
    --         ngx.log("failed to authenticate: ", err)
    --         return nil
    --     end
    -- end

    -- if ngx.var.reddb then
    --     local ok, err = red:select(ngx.var.reddb)
    --     if not ok then
    --         ngx.log("failed to select db: ", ngx.var.reddb, " ", err)
    --         return nil
    --     end
    -- end

    --string get
    local res, err = red:get(key)
    if not res then
        ngx.log(ngx.ERR, "failed to get kid: ", kid ,", ", err)
        return nil
    end

    if res == ngx.null then
        ngx.log(ngx.ERR, "key ", kid, " not found")
        return nil
    end

    local ok, err = red:set_keepalive(10000, 100) 
    if not ok then 
        ngx.log(ngx.ERR, "failed to close: ", err)
        return nil
    end
    
    return res
end

if os == nil
then
    ngx.exit(500) 
end

if version == nil
then
    ngx.exit(500) 
end

local cipherStr = redkey(os..":"..version)
if cipherStr == nil
then
    ngx.exit(500) 
end

local cipher = cjson_decode(cipherStr)
ngx.var.encrty_code = cipher["encrty"]

if ("POST" == request_method)
then
    ngx.req.read_body()
    local args = ngx.req.get_post_args()
    local q = tostring(args["q"])
    local sign = tostring(args["sign"])
    local aes_128_cbc_with_iv = assert(aes:new(cipher["decrypt"],
    nil, aes.cipher(128,"cbc"), {iv=iv}))
    local decrypt_data = ngx_decode_base64(q)
    if decrypt_data == nil 
    then 
        ngx.log(ngx.ERR, '=======>base64 err:')
        ngx.exit(500)
    end

    local param = aes_128_cbc_with_iv:decrypt(decrypt_data)
    if param == nil 
    then 
        ngx.log(ngx.ERR, '=======>param err:', param)
        ngx.exit(500)
    end

    local params = cjson_decode(param)
    if params == nil 
    then 
        ngx.log(ngx.ERR, '=======>params err:', params)
        ngx.exit(500)
    end

    local tamp = {}
    for i, v in pairs(params) do
        table.insert(tamp, i)
    end

    table.sort(tamp)
    local data = {}
    for i, v in pairs(tamp) do
        table.insert(data, v .."=" ..params[v])
    end
    
    local sign_data = table.concat(data, "&")
    sign_data = sign_data .. "&key="..cipher["key"]

    if (md5(sign_data) ~= string.lower(sign))
    then
        ngx.log(ngx.ERR, "=====>sign err:", md5(sign_data), sign)
        ngx.exit(500)
    end
   
    if ( math.abs(ngx.time() - params["timestamp"]) > 6000)
    then
        ngx.log(ngx.ERR, "=====>timestamp err:", params["timestamp"])
        ngx.exit(500)
    end

    ngx.req.set_body_data(table.concat(data, "&")) 
end
local random = resty_random.bytes(16)
ngx.var.iv_code = string.sub(str.to_hex(random), 8, 24)

