--[[

    DESCRIPTION

        Functions that are useful for debugging a parser.
        
        This is NOT meant for distribution via Live.
    
    VERSION
    
        2016.05.06.1    logPayload() accommodate new log length limitation
        2015.04.07.1    bugfix boolean "false" values
        2013.10.11.1    cli option to logTable()
        2013.05.08.1    function logPayload()
        2013.05.01.1    don't try to print function types
                        attempt not to traverse _G infinitely
        2013.03.07.1    print string "true" or "false" for boolean types
        2013.02.22.1    Initial development
                        function logTable()
--]]

local string = require('string')
local bit = require('bit')
local type = type
local pairs = pairs
local ipairs = ipairs
local logInfo = nw.logInfo
local table = require('table')
local math = require('math')
local isRequestStream = nw.isRequestStream
local isResponseStream = nw.isResponseStream
local print = print

module("debugParser")


--[[

Trying to modularize this.  In the meantime, put it at OnSessionBegin.

IMPORTANT:  Sometimes you have to import a pcap repeatedly to get a global to show up.  I don't
            know why.  Setting thread=1 doesn't seem to help.

    local function checkGlobals(checkTable)
        for idx, vlu in pairs(checkTable) do
            local idxType = type(vlu)
            if idxType ~="function" and idx ~= "_G" then
                if idxType == "table" then
                    checkGlobals(vlu)
                else
                    if idx ~= "_VERSION" and idx ~= "pi" and idx ~= "huge" then
                        nw.logInfo(idx .. ": " .. idxType)
                    end
                end
            end
        end
    end
    checkGlobals(_G)
    
--]]        

function logTable(dumpTable, nestLevel, cli)
    --[[
            Dumps a table (its values and sub-tables) to the log.
    --]]
    if nestLevel then
        if nestLevel == 255 then
            return
        end
        if type(nestLevel) == "boolean" then
            cli = nestLevel
            nestLevel = 0
        end
    end
    local logInfo = logInfo
    if cli then
        -- "cli" is an optional parameter:  if not nil then output will be printed rather than logged
        logInfo = print
    end
    local valueType = type(dumpTable)
    if valueType ~= "table" then
        logInfo("Not a table: " .. valueType)
        return
    end
    nestLevel = nestLevel or 0
    if nestLevel == 0 then
        logInfo("TABLE BEGIN " .. string.rep("-", 56) .. " TABLE BEGIN")
        nestLevel = nestLevel + 1
    end
    for i,j in pairs(dumpTable) do
        if type(j) == "table" then
            if (i == "_G" and nestLevel and nestLevel > 0) or i == dumpTable then
                -- fixme this is clumsy and doesn't work as intended anyway...
                return
            end
            if type(i) == "number" then
                logInfo(string.rep("    ", nestLevel) .. "index " .. i .. " is a table:")
                logTable(j, nestLevel + 1, cli)
                logInfo(string.rep("    ", nestLevel) .. "end of " .. i)
            else
                logInfo(string.rep("    ", nestLevel) .. "index '" .. i .. "' is a table:")
                logTable(j, nestLevel + 1, cli)
                logInfo(string.rep("    ", nestLevel) .. "end of '" .. i .. "'")
            end
        else
            if j ~= nil then
                if type(j) == "boolean" then
                    if j then
                        j = "true"
                    else
                        j = "false"
                    end
                end                    
                if type(i) == "number" then
                    logInfo(string.rep("    ", nestLevel) .. "index " .. i .. " value: " .. j)
                elseif type(j) == "function" then
                    logInfo(string.rep("    ", nestLevel) .. "index " .. i .. " is a function")
                else
                    logInfo(string.rep("    ", nestLevel) .. "index '" .. i .. "' value: " .. j)
                end
            else
                if type(i) == "number" then
                    logInfo(string.rep("    ", nestLevel) .. "index " .. i .. " has no value")
                else
                    logInfo(string.rep("    ", nestLevel) .. "index '" .. i .. "' has no value")
                end
            end
        end
    end
    if nestLevel == 1 then
        logInfo("TABLE END " .. string.rep("-", 60) .. " TABLE END")
    end
end

function logPayload(payload, label)
    --[[
            Dumps the given chunk of payload to the log, in a hex editor like format.
            
            NOTE:  default stream label is the stream from which the function was
                   called NOT the stream from which the payload object was extracted
    --]]
    if not payload then
        logInfo("logPayload: no payload")
        return
    end
    if type(payload) ~= "userdata" then
        logInfo("logPayload: not a payload object")
        return
    end
    label = label == nil and true
    local payloadChars, lineNum, line = {}, 0, {}
    table.insert(line, string.rep("_", 20))
    if type(label) == "boolean" and label then
        if isRequestStream() then
            table.insert(line, "In Request Stream ")
            table.insert(line, string.rep("_", 41))
        elseif isResponseStream() then
            table.insert(line, "In Response Stream")
            table.insert(line, string.rep("_", 41))
        else
            table.insert(line, "In Unknown Stream ")
            table.insert(line, string.rep("_", 41))
        end
    elseif type(label) == "string" then
        table.insert(line, label)
        table.insert(line, string.rep("_", 59 - string.len(label)))
    else
        table.insert(line, string.rep("_", 59))
    end
    table.insert(payloadChars, table.concat(line))
    line = {}
    table.insert(payloadChars, "           0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F    01234567 89ABCDEF")
    table.insert(line, string.format("%08x", lineNum))
    table.insert(line, "  ")
    local lineChars = {[1] = "  "}
    local numBytes = payload:len()
    for i = 1, numBytes do
        local thisByte = payload:byte(i)
        table.insert(line, string.format("%02x", thisByte))
        table.insert(line, " ")
        if thisByte < 32 or thisByte > 126 then
            table.insert(lineChars, ".")
        else
            table.insert(lineChars, string.char(thisByte))
        end
        if i < numBytes then
            if math.mod(i, 16) == 0 then
                table.insert(line, table.concat(lineChars))
                lineChars = {[1] = "  "}
                table.insert(payloadChars, table.concat(line))
                line = {}
                lineNum = lineNum + 16
                table.insert(line, string.format("%08x", i))
                table.insert(line, "  ")
            elseif math.mod(i, 8) == 0 then
                table.insert(line, " ")
                table.insert(line, " ")
            end
        else
            local leftoverBytes = math.mod(numBytes,16)
            if leftoverBytes > 0 then
                local fillSpaces = ((16 - leftoverBytes) * 3)
                if leftoverBytes <= 8 then
                    fillSpaces = fillSpaces + 1
                end
                table.insert(line, string.rep(" ", fillSpaces))
            end
            table.insert(line, table.concat(lineChars))
        end
    end
    table.insert(payloadChars, table.concat(line))
    line = {}
    table.insert(line, string.rep("_", 79))
    table.insert(payloadChars, table.concat(line))
    for i,j in ipairs(payloadChars) do
        logInfo(j)
    end
end