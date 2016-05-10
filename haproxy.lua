local dt = require "date_time"
local ip = require "ip_address"
local l = require 'lpeg'
local syslog = require "syslog"

require "cjson"

l.locale(l)

local msg = {
    Timestamp   = nil,
    Hostname    = nil,
    Payload     = nil,
    Pid         = nil,
    Fields      = nil
}

--[ read config variables ]
local conf_log_type = read_config('log_type')
local conf_captured_request_headers = read_config('captured_request_headers')
local conf_captured_response_headers = read_config('captured_response_headers')

--[ grammar ]
local syslog_grammar = syslog.build_rsyslog_grammar("%TIMESTAMP% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")

local sp                        = l.space
local timestamp                 = "[" * l.Cg(dt.build_strftime_grammar("%d/%b/%Y:%H:%M:%S") * dt.time_secfrac / dt.time_to_ns, "Timestamp") * "]"
local log_date                  = l.Cg(dt.build_strftime_grammar("%b %d %H:%M:%S"), "LogDate")
local host                      = (l.alnum^1 + l.S("-_"))^1
local fqdn                      = (l.alnum^1 + l.S("-_."))^1

local proc                      = l.P"haproxy[" * l.R("09")^1 * l.P"]:" * l.Cg(l.Cc"haproxy", "Type")
local remote_addr               = l.Cg(ip.v4, "remote_addr") * ":" * l.Cg(l.R("09")^1, "port")
local request                   = l.Cg(l.P(1)^0, "request")
local status                    = l.Cg(l.digit * l.digit * l.digit, "status")
local bytes                     = l.Cg(l.digit^1, "bytes")
local listener                  = l.Cg((l.alnum^1 + l.P("-"))^1, "listener")
local backend                   = l.Cg(host, "backend_name") * l.P"/" * l.Cg(host, "backend_server")

local slash                     = l.P"/"
local integer                   = (l.S("+-")^-1) * (l.digit^1)
local printusascii              = l.R"!~"
local nilvalue                  = l.P"-"

local Tq                        = l.Cg(integer / tonumber, "Tq")
local Tw                        = l.Cg(integer / tonumber, "Tw")
local Tc                        = l.Cg(integer / tonumber, "Tc")
local Tr                        = l.Cg(integer / tonumber, "Tr")
local Tt                        = l.Cg(integer / tonumber, "Tq")


local captured_request_cookie   = l.Cg( nilvalue + printusascii^-255 )
local captured_response_cookie  = l.Cg( nilvalue + printusascii^-255 )

local termination_state         = ( nilvalue + l.upper ) * ( nilvalue + l.upper ) * ( nilvalue + l.upper ) * ( nilvalue + l.upper )

local actconn                   = l.Cg(integer / tonumber, "actconn")
local feconn                    = l.Cg(integer / tonumber, "feconn")
local beconn                    = l.Cg(integer / tonumber, "beconn")
local srv_conn                  = l.Cg(integer / tonumber, "srv_conn")
local retries                   = l.P"+"^-1 * l.Cg(l.digit^1 / tonumber, "retries")

local pos_srv_queue             = l.Cg(integer / tonumber, "pos_srv_queue")
local pos_listener_queue        = l.Cg(integer / tonumber, "pos_listener_queue")

local captured_request_headers  = l.P"{" * l.Cg((1 - l.P"}")^0, "captured_request_headers") * l.P"}"
local captured_response_headers = l.P"{" * l.Cg((1 - l.P"}")^0, "captured_response_headers") * l.P"}"

local pattern = remote_addr
    * sp * timestamp
    * sp * listener
    * sp * backend
    * sp * Tq
    * slash * Tw
    * slash * Tc
    * slash * Tr
    * slash * Tt
    * sp * status
    * sp * bytes
    * sp * captured_request_cookie
    * sp * captured_response_cookie
    * sp * termination_state
    * sp * actconn
    * slash * feconn
    * slash * beconn
    * slash * srv_conn
    * slash * retries
    * sp * pos_srv_queue
    * slash * pos_listener_queue
    * sp * captured_request_headers
    * sp * captured_response_headers
    * sp * request

local msg = {
    Timestamp = nil,
    Type      = nil,
    Payload   = nil,
    Fields    = nil
}

local grammar = l.Ct(pattern)

-- Compatibility: Lua-5.0
-- http://lua-users.org/wiki/SplitJoin
function Split(str, delim, maxNb)
    -- Eliminate bad cases...
    if string.find(str, delim) == nil then
        return { str }
    end
    if maxNb == nil or maxNb < 1 then
        maxNb = 0    -- No limit
    end
    local result = {}
    local pat = "(.-)" .. delim .. "()"
    local nb = 0
    local lastPos
    for part, pos in string.gfind(str, pat) do
        nb = nb + 1
        result[nb] = part
        lastPos = pos
        if nb == maxNb then break end
    end
    -- Handle the last field
    if nb ~= maxNb then
        result[nb + 1] = string.sub(str, lastPos)
    end
    return result
end

function process_message ()
  local log = read_message("Payload")
  local fields = syslog_grammar:match(log)
  if not fields then return -1 end

  --[ fill blanks in defaults ]
  if conf_captured_request_headers == nil then conf_captured_request_headers = {} end
  if conf_captured_response_headers == nil then conf_captured_response_headers = {} end

  msg.Timestamp = fields.timestamp
  fields.timestamp = nil

  fields.programname = fields.syslogtag.programname
  msg.Pid = fields.syslogtag.pid or nil
  fields.syslogtag = nil

  msg.Hostname = fields.hostname
  fields.hostname = nil

  local m = grammar:match(fields.msg)
  if m then
    msg.Type      = m.Type
    msg.Payload   = nil
    msg.Timestamp = m.Timestamp

    -- split cookies

    -- parse request headers
    local split_reqs_hdr = {}
    for k,v in pairs(Split(m.captured_request_headers, '|')) do
      if conf_captured_request_headers[k] == nil then
        split_reqs_hdr[string.format("Header%d", k)] = v
      else
        split_reqs_hdr[conf_captured_request_headers[k]] = v
      end
    end

    split_reqs_hdr = cjson.encode(split_reqs_hdr)
    split_resp_hdr = Split(m.captured_response_headers, '|')

    -- fill fields
    fields.remote_addr               = m.remote_addr
    fields.request                   = m.request
    fields.status                    = m.status
    fields.bytes                     = m.bytes
    fields.protocol                  = m.protocol
    fields.backend_name              = m.backend_name
    fields.backend_server            = m.backend_server
    fields.http_host                 = m.http_host
    fields.tq                        = m.Tq
    fields.tw                        = m.Tw
    fields.tc                        = m.Tc
    fields.tr                        = m.Tr
    fields.tt                        = m.Tt
    fields.captured_request_cookie   = m.captured_request_cookie
    fields.captured_response_cookie  = m.captured_response_cookie

    fields.termination_state         = m.termination_state
    fields.actconn                   = m.actconn
    fields.feconn                    = m.feconn
    fields.beconn                    = m.beconn
    fields.srv_conn                  = m.srv_conn
    fields.retries                   = m.retries
    fields.pos_srv_queue             = m.pos_srv_queue
    fields.pos_listener_queue        = m.pos_listener_queue
    fields.captured_request_headers  = split_reqs_hdr
    fields.captured_response_headers = split_resp_hdr
  else
    -- Fail with return -1 or do whatever you want
    msg.Type = "Ignore"
    msg.Payload = fields.msg
  end
  fields.msg = nil

  msg.Fields = fields
  inject_message(msg)
  return 0
end
