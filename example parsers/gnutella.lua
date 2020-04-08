local parserName = "gnutella_lua"
local parserVersion = "2015.09.15.1"

local gnutella = nw.createParser(parserName, "Gnutella file sharing protocol", 6346)

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Identifies the Gnutella file sharing protocol.
]=]

summary.dependencies = {
    ["parsers"] = {
        "NETWORK"
    }
}

summary.conflicts = {
    ["parsers"] = {
        "GNUTELLA"
    }
}

summary.keyUsage = {
    ["action"]  = "gnutella command: 'connect', 'get'",
    ["service"] = "'6346'"
}

summary.liveTags = {
    "featured",
    "operations",
    "event analysis",
    "protocol analysis",
}

--[[
    VERSION

        2015.09.15.1  william motley          10.6.0.0.5648  reformat comments
        2014.08.12.1  william motley          10.4.0.0.3187  reset globals on StreamBegin
        2013.09.04.1  william motley          10.3.0.1506    Initial development (conversion from flex)


    OPTIONS

        none


    IMPLEMENTATION

        Conversion of flex parser "GNUTELLA" from NwFlex.parser.  Unlike the flex version, the token
        for "GET /get/" is only considered valid if a CONNECT token has been seen in the same stream
        in order to reduce false positives.


    TODO

        Extract filenames, etc.

--]]

gnutella:setKeys({
    nwlanguagekey.create("action")
})

function gnutella:beginOfStream()
    self.sawConnect = nil
end

function gnutella:connect()
    if nw.isRequestStream() then
        nw.createMeta(self.keys.action, "connect")
        self.sawConnect = true
    end
end

function gnutella:get1()
    if nw.isRequestStream() and self.sawConnect then
        nw.createMeta(self.keys.action, "get")
    end
end

function gnutella:get2()
    if nw.isRequestStream() then
        nw.createMeta(self.keys.action, "get")
    end
end

function gnutella:response()
    if nw.isResponseStream() then
        nw.setAppType(6346)
    end
end

gnutella:setCallbacks({
    [nwevents.OnStreamBegin] = gnutella.beginOfStream,
    ["^GNUTELLA CONNECT/"] = gnutella.connect,
    ["^GNUTELLA/"] = gnutella.response,
    ["^GET /get/"] = gnutella.get1,
    ["^GET /uri-res/N2R?"] = gnutella.get2,
})

return summary