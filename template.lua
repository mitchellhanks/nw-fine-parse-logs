local parserName = "fixme_parser_name_for_UI"
local parserVersion = "fixme_parser_version_number"
local PARSERNAME = nw.createParser(parserName, "fixme short parser description")
​nw.logDebug(parserName .. " " .. parserVersion) -- prints the parser name and version to /var/log/messages on loading when debug is on

-- fixme replace all occurances of PARSERNAME (case sensitive) with an internal name
-- for this parser - this name will not be seen or used outside this parser itself
​
--[=[
​   
    # This section is optional (for comments) and can contain whatever you like.  If you prefer, you can put
    # some (or all) of your instructions in your GitHub README and just reference it here.  It is recommended
    # to at least put a simple description and some implementation notes here.

    DESCRIPTION
​
        fixme long parser description
​
​
    VERSION HISTORY
​
        fixme changelog (this could be kept in GitHub instead)
​
​
    IMPLEMENTATION
​
        fixme how the parser works
​
​
    TODO
​
        fixme planned or needed changes
​
--]=]
​
local nwll = require('nwll')      -- fixme comment out if not needed.  Includes base NW lua function library
​
​
PARSERNAME:setKeys({
    nwlanguagekey.create("fixme - meta key name", nwtypes.fixme)   -- Set the appropriate meta key data type as defined in /modules/nw-api.lua
})
​
-- fixme comment out if not needed
function PARSERNAME:sessionBegin()
    -- reset session vars
    self.sessionVars = {}
end
​
-- fixme comment out if not needed
function PARSERNAME:streamBegin()
    -- reset stream vars
    self.streamVars = {}
end
​
-- example function when using a "token" callback
function PARSERNAME:fixme(token, first, last)
    -- fixme your parsing code here
end
​
-- example function when using a "meta" callback
function PARSERNAME:fixme(index, metavalue)
    -- fixme your parsing code here
end

PARSERNAME:setCallbacks({
    [nwevents.OnSessionBegin] = PARSERNAME.sessionBegin,  -- fixme comment out if not needed
    [nwevents.OnStreamBegin] = PARSERNAME.streamBegin,    -- fixme comment out if not needed
    ["fixme"] = PARSERNAME.fixme,  -- example of a "token" callback
    [nwlanguagekey.create("fixme.meta.key.name", nwtypes.fixme)] = PARSERNAME.fixme,  -- example of a "meta" callback
})