local parserName = "TLS_lua"
local parserVersion = "2019.12.04.1"

local tlsParser = nw.createParser(parserName, "SSL and TLS")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Identifies SSL 2.0 and 3.0, TLS 1.0, 1.1, 1.2, and 1.3.

Version is extracted from both the client and server hello, which
may lead to differing version meta for the same session.

SSL 2.0 is detected from the server handshake.  If the response
stream of an SSL 2.0 session is not seen or the server does not
offer a certificate, then the session will not be identified.
If the server responds with SSL 3.0 or TLS, the session will be
identified as SSL, and an alert for SSL 2.0 will not be registered.
]=]

summary.dependencies = {
    ["parsers"] = {
        "FeedParser",
        "NETWORK",
        "fingerprint_certificate",
        "nwll"
    },
    ["feeds"] = {
        "investigation"
    }
}

summary.conflicts = {
    ["parsers"] = {
        "TLSv1",
        "TLS-flex",
        "TLS_id"
    }
}

summary.keyUsage = {
    ["alias.host"]       = "service name indicator, if hostname",
    ["alias.ip"]         = "service name indicator, if ipv4",
    ["alias.ipv6"]       = "service name indicator, if ipv6",
    ["service"]          = "'443'",
    ["version"]          = "'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'",
    ["error"]            = "Alert message description",
    ["alert.id"]         = "mapped to risk meta",
    ["analysis.service"] = "TLS/SSL characteristics of interest",
    ["ioc"]              = "indicators of compromise",
    ["eoc"]              = "enablers of compromise"
}

summary.investigation = {
    ["analysis.service"] = {
        ["sni localhost"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "the server name indicator in an outbound TLS session is 'localhost'",
            ["reason"] = "",
        },
        ["SSL 2.0"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
            },
            ["description"] = "",
            ["reason"] = "",
        },
        ["SSL 3.0"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
            },
            ["description"] = "",
            ["reason"] = "",
        },
        ["ssl sni doesn't match http host"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "an http client specified different hostnames for an HTTP request and and SSL request to the same server",
            ["reason"] = "A domain fronting technique that can be used by malware hiding its true destination.  Is also commonly used legitimately by Content Delivery Networks.  Requires HTTP_lua.",
        },
    },
    ["ioc"] = {
        ["heartbleed data leak"] = {
            ["inv.category"] = {
                "threat",
            },
            ["inv.context"] = {
                "exploit",
            },
            ["description"] = "",
            ["reason"] = "",
            ["mitre"] = {
            },
        },
    },
    ["eoc"] = {
        ["openssl vulnerable to heartbleed"] = {
            ["inv.category"] = {
                "operations",
                "assurance"
            },
            ["inv.context"] = {
                "event analysis",
                "risk",
                "compliance",
            },
            ["description"] = "",
            ["reason"] = "",
            ["mitre"] = {
                "defense evasion:",
                "exfiltration:",
            },
        },
    },
}

summary.alertIDs = {
    ["info"] = {
        ["nw125005"] = "openssl vulnerable to heartbleed",
    },
    ["susicious"] = {
        ["nw125015"] = "ssl 3.0",
        ["nw125030"] = "ssl 2.0",
    },
    ["warning"] = {
        ["nw125010"] = "heartbleed data leak",
    }
}

summary.liveTags = {
    "operations",
    "event analysis",
    "protocol analysis",
}

--[[
    VERSION

        2019.12.04.1  william motley          11.4.0.0-10470.5  add "Ports Only" option
        2019.10.03.1  william motley          11.4.0.0-10440.5  use lowercase comparison for ssl sni doesn't match http host
        2019.09.19.1  william motley          11.4.0.0-10440.5  limit checking for SSL2 to once per stream
                                                                disable checking for server version vuln to HB
        2019.07.05.1  william motley          11.4.0.0-10087.1  get isHTTP and httpHosts to compare with SNI
        2019.05.02.1  william motley          11.4.0.0-9744.3   expand SSL 2.0 identification
                                                                register error meta for alert messages
        2019.03.13.1  william motley          11.4.0.0-9744.3   bugfix registerMeta()
        2019.03.06.2  william motley          11.4.0.0-9744.3   get direction from traffic_flow correctly
        2019.03.06.2  william motley          11.4.0.0-9744.3   be extra pedantic in checking whether decoder gives us garbage
                                                                duplicate hunting meta back to alert.id
        2019.02.27.1  william motley          11.4.0.0-9744.3   make sure nw.getPayload returns appropriate payload
        2019.01.24.1  william motley          11.3.0.0-9710.1   refactor, especially cert meta extraction
                                                                remove extraction of ciphersuites
                                                                move version meta to key "version"
                                                                add option to overwriteService service meta
                                                                get direction directly from traffic_flow
                                                                detect localhost directly from SNI
                                                                add TLS 1.3
                                                                UDM
        2018.08.16.1  william motley          11.3.0.0-9488.1   enhance identifification of single-sided sessions
        2016.09.13.1  william motley          11.0.0.0-7769.3   add ir alerts
        2016.03.07.1  william motley          10.6.0.0.6817     fix duplicated alert.id
        2016.03.03.1  william motley          10.6.0.0.6817     identify SSL 2.0
                                                                default "Register Version" from false to true
        2016.01.28.1  william motley          10.6.0.0.6817     allow 3 identification failed attempts before giving giving up
        2016.01.19.1  william motley          10.6.0.0.6817     rewrite tlsOther() again - check other stream if necessary
        2015.09.11.1  william motley          10.6.0.0.5648     reformat comments
        2015.08.05.1  william motley          10.6.0.0.5648     Extract servername from client hello if present
                                                                Bugfix: completely rewrite tlsOther()
        2015.06.05.1  william motley          10.5.0.0.4961     Bugfix: some local vars not declared as local
        2015.04.07.1  william motley          10.5.0.0.4961     Add option to register all common names
        2014.10.23.1  william motley          10.5.0.0.3764     Extraction of ciphersuite (conversion of HTTPS from native)
                                                                Option to register SSL/TLS version as crypto meta (popular request)
                                                                Fixed a bug which resulted in some sessions not being identified
        2014.10.16.2  william motley          10.5.0.0.3404     Add alert for SSL 3.0 in response to POODLE vulnerability
        2014.07.29.1  william motley          10.4.0.0.3187     Rework how options are set
        2014.04.16.2  william motley          10.3.3.0          Make identification via tlsOther pass through two stages of
                                                                length / position verification instead of just one
        2014.04.15.1  william motley          10.3.3.0          Call tlsOther from tlsHeartbeat to identify more sessions
                                                                Check that heartbeat length is more than message length (not just unequal)
        2014.04.11.2  william motley          10.3.3.0          Added SSL 3.0 to heartbleed detection
                                                                More surgical heartbleed request detection
        2014.04.11.1  william motley          10.3.3.0          Heartbleed FP mitigation: server must present a certificate
        2014.04.09.1  william motley          10.3.3.0          Add Heartbleed detection based on the work
                                                                of Ande Rutkiewicz (RSA CIRC)
        2013.08.21.1  william motley          10.3.0.1506       reinitialize thisCert each loop iteration (bug introduced
                                                                when thisCert was declared sooner)
        2013.06.26.1  william motley          10.2.5.1          wrap in pcall
                                                                bugfix: localize thisCert and declare sooner
        2013.06.17.1  william motley          10.2.5.1ish       assign permanent alert.id's
        2013.05.02.2  william motley          10.2.5.2          payload:short -> payload:uint16
                                                                payload:int -> payload:uint32
                                                                payload:byte -> payload:uint8
        2013.04.04.2  william motley          10.0.2.212        Check if a handshake follows a "tls-other" (some sessions weren't being identified)
        2012.10.31.1  william motley          9.8.4.11          Add options support
                                                                  - "register all authorities"
                                                                  - "register all serials"
        2012.10.03.1  william motley          9.8.4.11          Update to latest lua-parsing changes
                                                                Use nwll module
        2012.09.20.2  william motley          9.8.0.844         Optimize access to globals
        2012.09.20.1  william motley          9.8.0.844         Initial lua development


    OPTIONS

        "Overwrite Service": default false
        
            Default behavior is that if another parser has identified a session with service
            other than SSL, then this parser will not overwrite the service meta.
            
            If this option is enabled, then the parser will identify all sessions containing
            SSL as SSL even if a session has been identified by another parser as another
            service.
            
        "Ports Only": default false
        
            Default behavior is port-agnostic - the parser looks for all SSL/TLS sessions
            regardless of which ports a session uses.  This allows identification of encrypted
            sessions on unexpected and/or non-standard ports.
            
            If this option is enabled, then the parser will only look for SSL/TLS sessions
            using the configured ports.  Ports on other sessions will not be identified
            as SSL/TLS.  This may improve performance, at a cost of possibly decreased visibility.
            
            Note that a session on a configured port that is not SSL/TLS will still not be
            identified as SSL/TLS.  In other words, the parser doesn't assume that all sessions
            on configured ports are SSL/TLS.


    IMPLEMENTATION
            
            Identification requires seeing either an SSL token or end of stream following two consecutive
            ssl messages.  If there is only one message in the request stream, then the beginning of the
            response stream is instead checked for an ssl token.
                
            (SSL2 identification doesn't resemble the above at all...)
            
        The native HTTPS parser also registers "client" meta, which this parser does not.  However,
        it determines that information based entirely on destination port.  I've chosen not to
        continue that behavior as it is potentially erroneous and almost entirely useless.


    TODO
    
        Extraction of certificate meta from SSL 2.
            
--]]

local nwll=require("nwll")

local fingerprint_certificate
pcall(function() fingerprint_certificate = require("fingerprint_certificate") end)
if not (fingerprint_certificate and type(fingerprint_certificate) == "table" and fingerprint_certificate.extractCertificates) then
    fingerprint_certificate = nil
end

local traffic_flow
pcall(function()
    traffic_flow = require('traffic_flow')
    if not (traffic_flow and type(traffic_flow) == "table" and traffic_flow.subscribe) then
        traffic_flow = nil
    end
end)

local HTTP_lua

-- define options
    local options = {
        ["overwriteService"] = {
            ["name"] = "Overwrite Service",
            ["description"] = "Overwrite service meta set by other parsers",
            ["type"] = "boolean",
            ["default"] = false
        },
        ["portsOnly"] = {
            ["name"] = "Ports Only",
            ["description"] = "Look for SSL/TLS sessions on specific ports",
            ["type"] = "string",
            ["default"] = nil
        },
    }
-- set options DON'T MODIFY THIS SECTION
    pcall(function()
        local optionsModule = parserName .. "_options"
        optionsModule = require(optionsModule)
        for name,parameters in pairs(options) do
            if optionsModule[name] then
                parameters.value = optionsModule[name]()
            end
        end
    end)
    for name,parameters in pairs(options) do
        -- if the value was put in quotes, get the intended value not a string
        -- e.g., "100"  -> 100
        --       "true" -> true
        if parameters.type == "number" then
            parameters.value = tonumber(parameters.value)
        elseif parameters.type == "boolean" then
            if parameters.value == "false" then
                parameters.value = false
            elseif parameters.value == "true" then
                parameters.value = true
            end
        end
        -- make sure the type of value is correct, use default value if not
        -- e.g., expected a number but got "hello world" so use default instead
        if type(parameters.value) ~= parameters.type then
            parameters.value = parameters.default
        -- make sure number values fall within minimum and maximum
        elseif parameters.type == "number" then
            -- if the definition didn't provide a minimum, use 0
            parameters.minimum = (parameters.minimum and parameters.minimum > 0 and parameters.minimum) or 0
            -- if the definition didn't provide a maximum, use 4294967295
            parameters.maximum = (parameters.maximum and parameters.maximum < 4294967295 and parameters.maximum) or 4294967295
            parameters.value =
               (parameters.value < parameters.minimum and parameters.minimum) or
               (parameters.value > parameters.maximum and parameters.maximum) or
                parameters.value
        end
    end
-- end options

local indexKeys = {}
table.insert(indexKeys, nwlanguagekey.create("alias.host"))
table.insert(indexKeys, nwlanguagekey.create("alias.ip",nwtypes.IPv4))
table.insert(indexKeys, nwlanguagekey.create("alias.ipv6",nwtypes.IPv6))
table.insert(indexKeys, nwlanguagekey.create("version"))
table.insert(indexKeys, nwlanguagekey.create("error"))
table.insert(indexKeys, nwlanguagekey.create("analysis.service"))
table.insert(indexKeys, nwlanguagekey.create("ioc"))
table.insert(indexKeys, nwlanguagekey.create("eoc"))
table.insert(indexKeys, nwlanguagekey.create("alert.id"))

tlsParser:setKeys(indexKeys)

local sslPorts, sslTokens = {}, {}

local tlsVersions = {
    [0x0300] = "SSL 3.0",
    [0x0301] = "TLS 1.0",
    [0x0302] = "TLS 1.1",
    [0x0303] = "TLS 1.2"
}

function tlsParser:checkForToken(payload)
    if payload and payload:len() >= 3 then
        local sslTemp = payload:tostring(1, 3)
        if sslTemp and #sslTemp == 3 then
            -- first check for SSL3/TLS
            for i in pairs(sslTokens) do
                if i == sslTemp then
                    return true
                end
            end
            if not self.streamVars.ssl2_checked then
                self.streamVars.ssl2_checked = true
                -- check for SSL2
                if payload:len() == 5 then
                    local helloType = payload:uint8(3)
                    if helloType == 1 or helloType == 4 then
                        if payload:uint16(4, 5) == 2 then
                            self:registerMeta(self.keys["analysis.service"], "SSL 2.0")
                            return true
                        end
                    end
                end
            end
        end
    end
end

function tlsParser:registerMeta(key, vlu)
    if key and vlu then
        if self.sessionVars.isSSL then
            nw.createMeta(key, vlu)
        else
            if not self.sessionVars.unregisteredMeta then
              self.sessionVars.unregisteredMeta = {}
            end
            table.insert(self.sessionVars.unregisteredMeta, {[key] = vlu})
        end
    elseif not key and not vlu and self.sessionVars.isSSL and self.sessionVars.unregisteredMeta then
        -- register accumulated unregistered meta
        for idx, metaItem in ipairs(self.sessionVars.unregisteredMeta) do
            for key, vlu in pairs(metaItem) do
                if key and vlu then
                    nw.createMeta(key, vlu)
                end
            end
        end
        self.sessionVars.unregisteredMeta = nil
    end
    if not self.sessionVars.direction and traffic_flow then
        local flow = traffic_flow.subscribe()
        if flow and type(flow) == "table" and flow.direction and type(flow.direction) == "string" then
            self.sessionVars.direction = flow.direction
        end
    end
    if self.sessionVars.isSSL and not self.sessionVars.badssl and self.sessionVars.localhost and self.sessionVars.direction == "outbound" then
        nw.createMeta(self.keys["analysis.service"], "sni localhost")
        self.sessionVars.badssl = true
    end
end

function tlsParser:checkSSL2()
    if not self.streamVars.ssl2_checked then
        self.streamVars.ssl2_checked = true
        local payload = nw.getPayload(3, 7)
        if payload and payload:len() == 5 then
            if payload:uint8(1) == 4   -- server hello
            and payload:uint8(3) == 1  -- certificate type x.509
            and payload:uint16(4) == 2 -- SSL 2.0
            then
                if options.overwriteService.value or nw.getAppType() == 0 then
                    nw.setAppType(443)
                    if not self.sessionVars.badssl and self.sessionVars.localhost and self.sessionVars.direction == "outbound" then
                        nw.createMeta(self.keys["analysis.service"], "sni localhost")
                        self.sessionVars.badssl = true
                    end
                end
                nw.createMeta(self.keys["analysis.service"], "SSL 2.0")
                nw.createMeta(self.keys["alert.id"], "nw125030")
                nw.createMeta(self.keys.version, "SSL 2.0")
                self.sessionVars.isSSL = false
            end
        end
    end
end

local alerts = {
    [0] = "CLOSE_NOTIFY",
    [10] = "UNEXPECTED_MESSAGE",
    [20] = "BAD_RECORD_MAC",
    [21] = "DECRYPTION_FAILED",
    [22] = "RECORD_OVERFLOW",
    [30] = "DECOMPRESSION_FAILURE",
    [40] = "HANDSHAKE_FAILURE",
    [41] = "NO_CERTIFICATE",
    [42] = "BAD_CERTIFICATE",
    [43] = "UNSUPPORTED_CERTIFICATE",
    [44] = "CERTIFICATE_REVOKED",
    [45] = "CERTIFICATE_EXPIRED",
    [46] = "CERTIFICATE_UNKNOWN",
    [47] = "ILLEGAL_PARAMETER",
    [48] = "UNKNOWN_CA",
    [49] = "ACCESS_DENIED",
    [50] = "DECODE_ERROR",
    [51] = "DECRYPT_ERROR",
    [60] = "EXPORT_RESTRICTION",
    [70] = "PROTOCOL_VERSION",
    [71] = "INSUFFICIENT_SECURITY",
    [80] = "INTERNAL_ERROR",
    [90] = "USER_CANCELLED",
    [100] = "NO_RENEGOTIATION"
}

local handshakeProtocol = {
    [0] =   true,                   -- hello request
    [1] =   function(first, last)   -- client hello: extract version and SNI (server name indicator)
                if not first or not last then
                    return
                end
                local payload = nw.getPayload(first, last)
                if not payload then
                    return
                else
                    local payloadLength = payload:len()
                    if (payloadLength < 2) or (payload:len() ~= (last - first + 1)) then
                        return
                    end
                end
                local meta, extra = {}, {}
                local version = payload:uint16(1, 2)
                version = version and tlsVersions[version] or (bit.band(version, 0x7f00) == 0x7f00 and "TLS 1.3")
                if version then
                    table.insert(meta, {["version"] = version})
                    if version == "SSL 3.0" then
                        table.insert(meta, {["analysis.service"] = "SSL 3.0"})
                        table.insert(meta, {["alert.id"] = "nw125015"})
                    end
                end
                -- skip sessionid
                local temp = payload:uint8(35)
                if temp then
                    local position = 36 + temp
                    if position < last then
                        -- skip cipher suites
                        temp = payload:uint16(position)
                        if temp then
                            position = position + 2 + temp
                            if position < last then
                                -- skip compression methods
                                temp = payload:uint8(position)
                                if temp then
                                    position = position + 1 + temp
                                    if position < last then
                                        local extensionsEnd = payload:uint16(position)
                                        if extensionsEnd and extensionsEnd > 0 then
                                            extensionsEnd = position + extensionsEnd + 1
                                            position = position + 2
                                            -- extensions exist, loop through them until we find a
                                            -- server_name type (0x0000) or run out of extensions
                                            repeat
                                                local extLoop = false
                                                local extensionType = payload:uint16(position)
                                                if extensionType and extensionType ~= 0 then
                                                    local extensionLength = payload:uint16(position + 2)
                                                    if extensionLength then
                                                        position = position + 4 + extensionLength
                                                        if position < extensionsEnd then
                                                            extLoop = true
                                                        end
                                                    end
                                                else
                                                    -- found SNI
                                                    position = position + 7
                                                    local nameLength = payload:uint16(position)
                                                    if nameLength then
                                                        position = position + 2
                                                        local host, key = payload:tostring(position, position + nameLength - 1)
                                                        if host then
                                                            host, key = nwll.determineHostType(host)
                                                            if host and key then
                                                                table.insert(meta, {[key] = host})
                                                                extra.sni = extra.sni or {}
                                                                extra.sni[host] = true
                                                            end
                                                        end
                                                    end
                                                end
                                            until not extLoop
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
                return meta, extra
            end,
    [2] =   function(first, last)   -- server hello: extract version
                if not first or not last then
                    return
                end
                local payload = nw.getPayload(first, first +1)
                if payload and payload:len() == 2 then
                    local version = payload:uint16(1, 2)
                    version = version and tlsVersions[version] or (bit.band(version, 0x7f00) == 0x7f00 and "TLS 1.3")
                    if version then
                        local meta = {}
                        table.insert(meta, {["version"] = version})
                        if version == "SSL 3.0" then
                            table.insert(meta, {["analysis.service"] = "SSL 3.0"})
                            table.insert(meta, {["alert.id"] = "nw125015"})
                        end
                        return meta
                    end
                end
            end,
    [11] =  function(first, last)   -- certificate: extract cert meta (CA, subject, serial number)
                if not first or not last then
                    return
                end
                if fingerprint_certificate then
                    -- first three bytes are length of the chain
                    local payload = nw.getPayload(first, first + 2)
                    if payload and payload:len() == 3 then
                        local position = first + 3
                        local tempShort = payload:uint16(1)
                        local tempByte = payload:uint8(3)
                        if tempShort and tempByte then
                            local chainLength = bit.bor(bit.lshift(tempShort, 8), tempByte)
                            -- last byte of handshake and last byte of chain should align
                            if chainLength and (first + 3 + chainLength - 1 == last) then
                                fingerprint_certificate.extractCertificates(first)
                            end
                        end
                    end
                end
            end,
    [12] =  true,                   -- server key exchange
    [13] =  true,                   -- certificate request
    [14] =  true,                   -- server hello done
    [15] =  true,                   -- certificate verify
    [16] =  true,                   -- client key exchange
    [20] =  true,                   -- finished
}

-- callback functions

function tlsParser:HBserverCheck(idx, vlu)
    -- pre or post session begin doesn't matter here
    vlu = string.lower(vlu)
    if string.find(vlu, "^.*openssl/1%.0%.1[abcdef]") then
        nw.createMeta(self.keys["alert.id"], "nw125005")
        nw.createMeta(self.keys.eoc, "openssl vulnerable to heartbleed")
    end
end

-- event functions

function tlsParser:sessionBegin()
    -- reset session vars
    self.sessionVars = {
        --[[
            ["isSSL"],
            ["hbReqs"] = {},
            ["unregisteredMeta"] = {}
            ["direction"],
            ["localhost"],  -- true if the SNI is "localhost"
            ["badssl"],     -- the "sni localhost" alert has already been registered, don't do it again
        --]]
    }
end

function tlsParser:streamBegin()
    -- reset stream vars
    self.streamVars = {
        --[[
            ["tlsOtherAttempts"],
        --]]
    }
end

-- token functions

function tlsParser:tlsOther(token, first, last)
    --[=[
        Identification requires seeing either an SSL token or end of stream
        following two consecutive ssl messages.  If there is only one
        message in the request stream, then the beginning of the response
        stream is instead checked for an ssl token.
    --]=]
    if self.sessionVars.isSSL == nil then
        if nw.getAppType() == 443 then
            -- something else has already identified this as SSL
            self.sessionVars.isSSL = true
            self:registerMeta()
            return
        end
        local thisStream
        if nw.isRequestStream() then
            thisStream = 1
            self.sessionVars.sawRequestStream = true
        else
            thisStream = 2
        end
        local streamPayloadBytes = self.streamVars.streamPayloadBytes
        if not streamPayloadBytes then
            local packets, bytes, payloadBytes, retPackets, retPayload = nwstream.getStats()
            streamPayloadBytes = (payloadBytes and retPayload) and payloadBytes - retPayload
            self.streamVars.streamPayloadBytes = streamPayloadBytes
        end
        -- get to the end of this ssl message
        local position = last + 1
        local payload = nw.getPayload(position, position + 1)
        if payload and payload:len() == 2 then
            position = position + 2 + payload:uint16(1, 2)
            -- are we beyond the end of this stream?
            if position < streamPayloadBytes then
                -- still within stream
                payload = nw.getPayload(position, position + 4)
                if payload and payload:len() == 5 then
                    -- is there an ssl token here?
                    if self:checkForToken(payload) then
                        -- yes, get to the end of this ssl message
                        position = position + 5 + payload:uint16(4, 5)
                        -- are we beyond the end of this stream?
                        if position < streamPayloadBytes then
                            -- still within stream
                            payload = nw.getPayload(position, position + 2)
                            if payload and payload:len() == 3 then
                                -- is there an ssl token here?
                                if self:checkForToken(payload) then
                                    -- yes, identify
                                    self.sessionVars.isSSL = true
                                    if options.overwriteService.value or nw.getAppType() == 0 then
                                        nw.setAppType(443)
                                    end
                                    self:registerMeta()
                                    return
                                end
                            end
                        elseif position == streamPayloadBytes + 1 then
                        -- just beyond end of stream (message length was valid), so identify
                            self.sessionVars.isSSL = true
                            if options.overwriteService.value or nw.getAppType() == 0 then
                                nw.setAppType(443)
                            end
                            self:registerMeta()
                            return
                        end
                    end
                end
            elseif position == streamPayloadBytes + 1 then
                -- just beyond end of stream (message length was valid)
                -- are we in the request stream?
                if thisStream == 1 then
                    -- yes, get the response stream
                    local stream = nwsession.getResponseStream()
                    -- is there a response stream?
                    if stream then
                        -- yes, does it contain payload?
                        payload = nwstream.getPayload(stream, 1, 5)
                        if payload and payload:len() >= 3 then
                            -- yes, does it begin with an ssl token?
                            if self:checkForToken(payload) then
                                -- yes, identify
                                self.sessionVars.isSSL = true
                                if options.overwriteService.value or nw.getAppType() == 0 then
                                    nw.setAppType(443)
                                end
                                self:registerMeta()
                                return
                            end
                        elseif not payload or payload:len() == 0 then
                            -- no payload, identify
                            self.sessionVars.isSSL = true
                            if options.overwriteService.value or nw.getAppType() == 0 then
                                nw.setAppType(443)
                            end
                            self:registerMeta()
                            return
                        end
                    else
                        -- no response stream, identify
                        self.sessionVars.isSSL = true
                        if options.overwriteService.value or nw.getAppType() == 0 then
                            nw.setAppType(443)
                        end
                        self:registerMeta()
                        return
                    end
                elseif not self.sessionVars.sawRequestStream then
                    -- in response stream but haven't seen request stream yet
                    local stream = nwsession.getRequestStream()
                    -- is there a request stream?
                    if stream then
                        -- yes, does it contain payload?
                        payload = nwstream.getPayload(stream, 1, 5)
                        if payload and payload:len() >= 3 then
                            -- does it begin with an ssl token?
                            if self:checkForToken(payload) then
                                -- yes, identify
                                self.sessionVars.isSSL = true
                                if options.overwriteService.value or nw.getAppType() == 0 then
                                    nw.setAppType(443)
                                end
                                self:registerMeta()
                                return
                            end
                        elseif not payload or payload:len() == 0 then
                            -- no payload, identify
                            self.sessionVars.isSSL = true
                            if options.overwriteService.value or nw.getAppType() == 0 then
                                nw.setAppType(443)
                            end
                            self:registerMeta()
                            return
                        end
                    else
                        -- no request stream, identify
                        -- I don't think this can actually happen, but it's here just in case
                        self.sessionVars.isSSL = true
                        if options.overwriteService.value or nw.getAppType() == 0 then
                            nw.setAppType(443)
                        end
                        self:registerMeta()
                        return
                    end
                end
            end
        end
        -- if we're here then identification failed
        self.sessionVars.failCount = (self.sessionVars.failCount and self.sessionVars.failCount + 1) or 1
        -- three strikes yer out
        if self.sessionVars.failCount == 3 then
            self.sessionVars.isSSL = false
        end
    end
end

function tlsParser:tlsHandshake(token, first, last)
    if self.sessionVars.isSSL == nil then
        if options.portsOnly.value and #sslPorts > 0 then
            local transport, srcPort, dstPort = nw.getTransport()
            if srcPort and dstPort then
                local match
                for idx, port in ipairs(sslPorts) do
                    if srcPort == port or dstPort == port then
                        match = true
                        break
                    end
                end
                if not match then
                    return
                end
            end
        end
        self:tlsOther(token, first, last)
    end
    if self.sessionVars.isSSL ~= false then
        local position = last + 1
        -- Next two bytes are length of the record layer (essentially a message length)
        local payload = nw.getPayload(position, position + 1)
        if payload and payload:len() == 2 then
            local messageLast = position + 1 + payload:uint16(1)
            position = position + 2
            -- there may be multiple handshakes in a single message
            repeat
                local handshakeLoop = false
                -- Next byte is handshake type, followed by three bytes for handshake length
                payload = nw.getPayload(position, position + 3)
                if payload and payload:len() == 4 then
                    local handshakeType = payload:uint8(1)
                    if handshakeType and handshakeProtocol[handshakeType] then
                        position = position + 4
                        local tempShort = payload:uint16(2)
                        local tempByte = payload:uint8(4)
                        if tempShort and tempByte then
                            local handshakeLast = position + bit.bor(bit.lshift(tempShort, 8), tempByte) - 1
                            if handshakeLast and (handshakeLast <= messageLast) then
                                if type(handshakeProtocol[handshakeType]) == "function" then
                                    local meta, extra = handshakeProtocol[handshakeType](position, handshakeLast)
                                    if meta then
                                        for idx, metaItem in ipairs(meta) do
                                            if metaItem then
                                                for key, value in pairs(metaItem) do
                                                    if key and value and self.keys[key] then
                                                        self:registerMeta(self.keys[key], value)
                                                    end
                                                end
                                            end
                                        end
                                    end
                                    if extra then
                                        if extra.sni then
                                            if extra.sni.localhost then
                                                self.sessionVars.localhost = true
                                            end
                                            if HTTP_lua == nil then
                                                pcall(function() HTTP_lua = require('HTTP_lua') end)
                                                if not (HTTP_lua and type(HTTP_lua) == "table" and HTTP_lua.HTTP_session) then
                                                    HTTP_lua = false
                                                end
                                            end
                                            if HTTP_lua then
                                                local HTTP_session = self.sessionVars.HTTP_session
                                                if HTTP_session == nil then
                                                    HTTP_session = HTTP_lua.HTTP_session()
                                                    self.sessionVars.HTTP_session = HTTP_session
                                                end
                                                if HTTP_session == true then
                                                    local http_hosts = self.sessionVars.http_hosts
                                                    if not http_hosts then
                                                        http_hosts = HTTP_lua.getHosts()
                                                        if http_hosts and type(http_hosts) == "table" then
                                                            local hosts_lower = {}
                                                            for host in pairs(http_hosts) do
                                                                host = string.lower(host)
                                                                if host then
                                                                    hosts_lower[host] = true
                                                                end
                                                            end
                                                            self.sessionVars.http_hosts = hosts_lower
                                                            http_hosts = hosts_lower
                                                        end
                                                    end
                                                    if http_hosts and type(http_hosts) == "table" then
                                                        for host in pairs(extra.sni) do
                                                            host = string.lower(host)
                                                            if host and not http_hosts[host] then
                                                                self:registerMeta(self.keys["analysis.service"], "ssl sni doesn't match http host")
                                                            end
                                                        end
                                                    end
                                                end
                                            end
                                        end
                                    end
                                end
                                position = handshakeLast + 1
                                if position < messageLast then
                                    handshakeLoop = true
                                end
                            end
                        end
                    end
                end
            until not handshakeLoop
        end
    end
end

function tlsParser:tlsAlert(token, first, last)
    if self.sessionVars.isSSL == nil then
        self:tlsOther(token, first, last)
    end
    if self.sessionVars.isSSL ~= false then
        local payload = nw.getPayload(last + 1, last + 4)
        if payload and payload:len() == 4 then
            local length = payload:uint16(1)
            local level = payload:uint8(3)
            local description = payload:uint8(4)
            if (length and length == 2) and (level and (level == 1 or level == 2)) and description then
                if alerts[description] then
                    self:registerMeta(self.keys.error, alerts[description])
                end
            end
        end 
    end
end

function tlsParser:tlsHeartbeat(token, first, last)
    if self.sessionVars.isSSL == nil then
        self:tlsOther(token, first, last)
    end
    if self.sessionVars.isSSL ~= false then
        local payload = nw.getPayload(last + 1, last + 5)
        if payload and payload:len() == 5 then
            local hbType = payload:uint8(3)
            if hbType then
                if hbType == 1 then
                    local msgLength = payload:uint16(1)
                    local hbLength = payload:uint16(4)
                    if (msgLength and hbLength) and msgLength < hbLength then
                        local hbReqs = self.sessionVars.hbReqs or {}
                        hbReqs[hbLength] = true
                        self.sessionVars.hbReqs = hbReqs
                    end
                elseif hbType == 2 and self.sessionVars.isSSL then
                    local hbLength = payload:uint16(4)
                    if self.sessionVars.hbReqs and self.sessionVars.hbReqs[hbLength] then
                        self:registerMeta(self.keys.ioc, "heartbleed data leak")
                        self:registerMeta(self.keys["alert.id"], "nw125010")
                    end
                end
            end
        end
    end
end

function tlsParser:onPort()
    if self.sessionVars.isSSL == nil then
        if nw.getAppType() == 443 then
            -- something else has already identified this as SSL
            self.sessionVars.isSSL = true
            self:registerMeta()
            return
        end
        -- Is there an SSL token here?  Need 3 bytes minimum for SSL3/TLS, may need 5 if SSL 2.0
        local payload = nw.getPayload(1, 5)
        if payload and #payload >= 3 then
            if self:checkForToken(payload) then
                -- yes, call tlsOther - this will have the same effect as if it had
                -- been called from a token match at the beginning of the stream
                tlsParser:tlsOther(nil, 1, 3)
            end
        end
    end
end

local callbacks = {
    [nwevents.OnSessionBegin] = tlsParser.sessionBegin,
    [nwevents.OnStreamBegin] = tlsParser.streamBegin,
    [nwevents.OnSessionEnd] = tlsParser.sessionEnd,
    -- always need to match on handshake (only other way to get certificates would be to iterate every SSL/TLS message looking for them)
    ["\022\003\000"] = tlsParser.tlsHandshake,   -- Handshake SSL 3.0
    ["\022\003\001"] = tlsParser.tlsHandshake,   -- Handshake TLS 1.0
    ["\022\003\002"] = tlsParser.tlsHandshake,   -- Handshake TLS 1.1
    ["\022\003\003"] = tlsParser.tlsHandshake,   -- Handshake TLS 1.2
}

if options.portsOnly.value then
    -- only look for SSL/TLS on optionally-configured ports
    for port in string.gmatch(options.portsOnly.value, "[^%s,]+") do
        local portNum = tonumber(port)
        if portNum and portNum >= 1 and portNum <= 65535 then
            table.insert(sslPorts, portNum)
        else
            nw.logWarning("TLS_lua ignoring invalid port '" .. port .. "'")
        end
    end
    if #sslPorts == 0 then
        nw.logWarning("TLS_lua no valid ports, defaulting to port-agnostic")
    end
end

sslTokens = {
    ["\020\003\000"] = tlsParser.tlsOther,       -- ChangeCipherSpec SSL 3.0
    ["\020\003\001"] = tlsParser.tlsOther,       -- ChangeCipherSpec TLS 1.0
    ["\020\003\002"] = tlsParser.tlsOther,       -- ChangeCipherSpec TLS 1.1
    ["\020\003\003"] = tlsParser.tlsOther,       -- ChangeCipherSpec TLS 1.2
    ["\021\003\000"] = tlsParser.tlsAlert,       -- Alert SSL 3.0
    ["\021\003\001"] = tlsParser.tlsAlert,       -- Alert TLS 1.0
    ["\021\003\002"] = tlsParser.tlsAlert,       -- Alert TLS 1.1
    ["\021\003\003"] = tlsParser.tlsAlert,       -- Alert TLS 1.2
    ["\022\003\000"] = tlsParser.tlsHandshake,   -- Handshake SSL 3.0
    ["\022\003\001"] = tlsParser.tlsHandshake,   -- Handshake TLS 1.0
    ["\022\003\002"] = tlsParser.tlsHandshake,   -- Handshake TLS 1.1
    ["\022\003\003"] = tlsParser.tlsHandshake,   -- Handshake TLS 1.2
    ["\023\003\000"] = tlsParser.tlsOther,       -- Application SSL 3.0
    ["\023\003\001"] = tlsParser.tlsOther,       -- Application TLS 1.0
    ["\023\003\002"] = tlsParser.tlsOther,       -- Application TLS 1.1
    ["\023\003\003"] = tlsParser.tlsOther,       -- Application TLS 1.2
    ["\024\003\000"] = tlsParser.tlsHeartbeat,   -- Heartbeat SSL 3.0
    ["\024\003\001"] = tlsParser.tlsHeartbeat,   -- Heartbeat TLS 1.0
    ["\024\003\002"] = tlsParser.tlsHeartbeat,   -- Heartbeat TLS 1.1
    ["\024\003\003"] = tlsParser.tlsHeartbeat,   -- Heartbeat TLS 1.2
    -- check for ssl2 if a certificate is seen
    ["\006\003\085\004\010"] = tlsParser.checkSSL2,  -- 0x060355040A
    ["\006\003\085\004\003"] = tlsParser.checkSSL2,  -- 0x0603550403
    ["\048\030\023\013"]     = tlsParser.checkSSL2,  -- 0x301E170D
}

if #sslPorts > 0 then
    for idx, port in ipairs(sslPorts) do
        callbacks[port] = tlsParser.onPort
    end
else
    for token, func in pairs(sslTokens) do
        callbacks[token] = func
    end
end
    
tlsParser:setCallbacks(callbacks)

return summary