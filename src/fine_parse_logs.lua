local parserName = "fine_parse_logs"
local parserVersion = "1.0"
local fineparse = nw.createParser(parserName, "Fine parse logs using Lua pattern matching.")
nw.logDebug(parserName .. " " .. parserVersion)

--[[    FINE_PARSE_LOGS.LUA

        Use Lua patterns to extract values from raw logs in RSA NetWitness Platform.

        This is a community parser, found on GitHub:  https://github.com/mitchellhanks/nw-fine-parse-logs

        See the project README on GitHub for instructions, downloads and version history.
        
        Current version can be found above in the "parserVersion" parameter.
        
        CAUTION: See project README regarding potential negative impact to performance in using this parser.

        CAUTION: This parser WILL NOT LOAD without the fine_parse_logs_options.lua file deployed and properly configured.  
        The options file is also available on the GitHub repo with instructions.
        --]]
        
local indexKeys = {}  -- Will use this table to contain meta key names we will register output to.
        
-- functions
    function fineparse:SessionBegin()
        -- Reset global values
        self.sessionVars = {}
    end

    function arraysplit (inputstr, sep)
        if sep == nil then
            sep = "%s"
        end        
        local t={}
        for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
            table.insert(t, str)
        end        
        return t
    end    

    function validate(val,datatype,required)
        if required ~=nil and required ~= 0 and required ~= "0" and required ~= "no" and required ~= "No" and required ~= "NO" and required ~= "" and (val == nil or val == "") then
            return false
        elseif val == nil or val == "" then
            return true
        elseif type(val) == datatype then
            return true
        else
            return false
        end
    end

    function fineparse:extractInfo(idx, metaval)
        -- Loop through conditions table for this callback and search on each condition
        
        -- NOTE: This for loop will only execute if the value from the callback matches one of the 
        -- values included in the options file entries (the "metaval").  Otherwise it will exit before 
        -- extracting any payload or doing anything else at this point.
        for index,condition in ipairs(conditions[metaval]) do
            -- Extract the parameters from the conditions table
            local pattern = condition[1]
            local metakey = condition[2]
            local isarray = condition[3]
            local arraydelim = condition[4]

            local payload = nw.getPayload(1,-1)
            local rawlog = payload:tostring(1,-1)

            if rawlog ~= nil and type(rawlog) == "string" then
                tmatch = {}
                for tmatch in string.gmatch(rawlog, pattern) do
                    if tmatch ~= nil then
                        if isarray ~= nil and type(isarray) == "number" and isarray == 1 then
                            tmembers=arraysplit(tmatch,arraydelim)
                            for index,entry in ipairs(tmembers) do
                                nw.createMeta(self.keys[metakey], entry)
                            end
                        else
                            nw.createMeta(self.keys[metakey], tmatch)
                        end
                    end
                end
            end
        end
    end

    -- end functions
    
-- read options file
    local params = {}
    conditions={}
    keysUsed={}

    
    -- Safely call the options module and read from the options file
    local status, error = pcall(function()
        local optionsModule = parserName .. "_options"
        optionsModule = require(optionsModule)
        params = optionsModule["get_search_conditions"]()
    end)
    if not status then
        nw.logFailure(parserName .. ": Error loading required options file. Parser cannot load: " .. error)
        return
    end

    -- Validate options file entries
    for index,entry in ipairs(params) do
        local badparam = 0
        if validate(entry.callbackval,"string", 1) then
            if validate(entry.metakey, "string", 1) then
                if validate(entry.pattern, "string", 1) then
                    if validate(entry.isarray, "number", 0) then 
                        if entry.isarray then
                            if validate(entry.arraydelim, "string", 1) then
                                badparam = nil
                            else
                                badparam = "arraydelim"
                            end
                        else
                            badparam = nil
                        end
                    else
                        badparam = "isarray"
                    end
                else
                    badparam = "pattern"
                end
            else
                badparam = "metakey"
            end
        else
            badparam = "callbackval"
        end

        if badparam then
            nw.logFailure(parserName .. ": ERROR: Missing or invalid parameter [ " .. badparam  .. " ] in options file entry " .. index .. ".  Parser cannot load.")
            return --This will exit the parser without loading or executing its callbacks, effectively disabling it.
        end

        -- Add search condition/pattern for the current callback value
        if type(conditions[entry.callbackval]) ~= "table" then
            conditions[entry.callbackval] = {}
        end
        table.insert(conditions[entry.callbackval], {entry.pattern,entry.metakey,entry.isarray,entry.arraydelim})

        -- Create entry in indexKeys table if it doesn't already exist
        if keysUsed[entry["metakey"]] == nil then
            keysUsed[entry["metakey"]] = 1
            table.insert(indexKeys, nwlanguagekey.create(entry["metakey"]))
        end
    end
    -- end options

fineparse:setKeys(indexKeys)

fineparse:setCallbacks({
    [nwevents.OnSessionBegin] = fineparse.sessionBegin,
    [nwlanguagekey.create("device.type", nwtypes.Text)] = fineparse.extractInfo,
})
