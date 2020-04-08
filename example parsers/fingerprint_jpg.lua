local parserName = "fingerprint_jpg_lua"
local parserVersion = "2015.09.15.1"

local jpg = nw.createParser(parserName, "JPEG image file detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detects JPEG image files.
]=]

summary.conflicts = {
    ["parsers"] = {
        "fingerprint_jpg"
    }
}

summary.keyUsage = {
    ["filetype"] = "'jpg'"
}

summary.liveTags = {
    "featured",
    "operations",
    "event analysis",
    "file analysis",
}

--[[
    VERSION

        2015.09.15.1  william motley          10.6.0.0.5648  reformat comments
        2013.08.06.1  william motley          10.3.0.1506    Initial development


    OPTIONS

        none


    IMPLEMENTATION

        Straight conversion of flex "fingerprint_jpg" parser.


    TOD

        none

--]]

jpg:setKeys({
    nwlanguagekey.create("filetype")
})

function jpg:header()
    nw.createMeta(self.keys.filetype, "jpg")
end

jpg:setCallbacks({
--   0x ff  d8  ff  e0  00  10  4a  46  49  46  00
    ["\255\216\255\224\000\016\074\070\073\070\000"] = jpg.header,
})

return summary