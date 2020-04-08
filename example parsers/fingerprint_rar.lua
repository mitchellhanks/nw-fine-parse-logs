local parserName = "fingerprint_rar_lua"
local parserVersion = "2015.09.15.1"

local rar = nw.createParser(parserName, "RAR archive detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detects RAR archive files.  Registers names of files within archive 
files if available.

A rar may be password protected or encrypted.  An encrypted rar is 
always password protected - in which case, only the "encrypted" alert 
is registered.

Filenames extracted are names of the files within the archive, not the 
name of the archive itself.

Filenames can be extracted from a passord protected rar, but not an 
encrypted rar.

For a base64-encoded rar, only "encrypted" is detected, not "password 
protected".  No filenames are extracted.
]=]

summary.dependencies = {
    ["parsers"] = {
        "FeedParser",
        "nwll"
    },
    ["feeds"] = {
        "investigation",
    }
}

summary.conflicts = {
    ["parsers"] = {
        "fingerprint_rar",
        "encoded_file_fingerprinting"
    }
}

summary.keyUsage = {
    ["alert.id"]  = "mapped to risk meta",
    ["directory"] = "directory of file within archive",
    ["extension"] = "extension of file within archive",
    ["filename"]  = "name of file within archive",
    ["filetype"]  = "'rar'"
}

summary.investigation = {
    ["analysis.file"] = {
        ["rar file password protected"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
            },
            ["description"] = "",
            ["reason"] = "",
        },
        ["rar file encrypted"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
            },
            ["description"] = "",
            ["reason"] = "",
        },
    }
}

summary.alertIDs = {
    ["suspicious"] = {
        ["nw05390"] = "rar file password protected",
        ["nw05395"] = "rar file encrypted"
    }
}

summary.liveTags = {
    "featured",
    "malware analysis",
    "spectrum",
    "malware analysis",
    "spectrum",
    "operations",
    "event analysis",
    "file analysis",
}

--[[
    VERSION

        2015.09.15.1  william motley          10.6.0.0.5648  reformat comments
        2013.11.18.1  william motley          10.3.0.2117    Detect encrypted in base64
        2013.10.03.1  william motley          10.3.0.1785    Added base64
        2013.08.27.1  william motley          10.3.0.1506    Initial development


    OPTIONS

        none


    IMPLEMENTATION

        This is _NOT_ a conversion of the flex fingerprint_rar parser, even though they both
        identify rar files.  Rather, this is a rewrite and expansion - it does more, better.

        Improvements:

            - Identification of new v5 format
            - Extraction of names of filenames from within the archive
            - Detection of password-protected and encrypted

        v4 format documentation:  http://kthoom.googlecode.com/hg/docs/unrar.html

        v5 format documentation:  http://www.rarlab.com/technote.htm


    TODO

        V4 blocks don't have a block-size header.  "File" block size is calculated
        from header size and packed-file size.  So V4 filename extraction will break
        once a non "file" header is hit.  However, seems like all file blocks should
        be congruent?  In which case this isn't a problem.  Need examples to test...

        Also for V4, if the EXT_TIME flag is set in the file header, then there is a
        variable number of bytes at the end of the packed data, which I can't find
        documentation for.  So V4 filename extraction may also break if EXTTIME is
        present.

--]]

nw.logDebug(parserName .. " " .. parserVersion)

local nwll = require('nwll')

local alerts = ({
    ["password"] =  "nw05390",
    ["encrypted"] = "nw05395"
})

rar:setKeys({
    nwlanguagekey.create("filetype"),
    nwlanguagekey.create("directory"),
    nwlanguagekey.create("filename"),
    nwlanguagekey.create("extension"),
    nwlanguagekey.create("alert.id")
})

function rar:v4(token, first, last)
    local status, error = pcall(function(token, first, last)
        -- get header type, flags, and size
        local payload = nw.getPayload(last + 3, last + 7)
        if payload and payload:len() == 5 then
            local headerType = payload:uint8(1)
            -- Must be 0x73 ("MAIN")
            if headerType ~= 0x73 then
                return
            end
            nw.createMeta(self.keys.filetype, "rar")
            local headerFlags = payload:uint16(2, true)
            if bit.band(headerFlags, 128) == 128 then
                -- encrypted
                nw.createMeta(self.keys["alert.id"], alerts["encrypted"])
                return
            end
            -- not encrypted, skip rest of main header then extract filenames
            local headerLength = payload:uint16(4, true)
            local streamPosition = last + headerLength + 3
            local passwordDetected = false
            repeat
                local loopControl = 0
                -- get bytes for type, flags, header size, packed size
                local payload = nw.getPayload(streamPosition, streamPosition + 6)
                if payload and payload:len() == 7 then
                    local headerType = payload:uint8(1)
                    if headerType == 0x74 then -- "FILE"
                        -- flags are not little-endian, even though everything else is...
                        local headerFlags = payload:uint16(2)
                        local headerLength = payload:uint16(4, true)
                        local packedLength = payload:uint16(6, true)
                        if not passwordDetected then
                            if bit.band(headerFlags, 4) == 4 then
                                nw.createMeta(self.keys["alert.id"], alerts["password"])
                                passwordDetected = true
                            end
                        end
                        local position = streamPosition + 24
                        local nameLength = nwpayload.uint16(nw.getPayload(position, position + 1), 1, true)
                        if nameLength then
                            position = position + 6
                            if bit.band(headerFlags, 256) == 256 then
                                position = position + 8
                            end
                            local archivedFilename = nwpayload.tostring(nw.getPayload(position, position + nameLength - 1), 1, -1)
                            if archivedFilename then
                                local dir, file, ext = nwll.extractPathElements(archivedFilename)
                                if dir then
                                    nw.createMeta(self.keys.directory, dir)
                                end
                                if file then
                                    nw.createMeta(self.keys.filename, file)
                                end
                                if ext then
                                    nw.createMeta(self.keys.extension, ext)
                                end
                                streamPosition = streamPosition + headerLength + packedLength
                                loopControl = 1
                            end
                        end
                    end
                end
            until loopControl == 0
        end
    end, token, first, last)
    if not status and debugParser then
        nw.logFailure(error)
    end
end

function rar:vintRead(payload, position, le)
    -- V5 uses a concept of "vint" (variable length integer).  The 7 least
    -- significant bits of each byte are a value.  The most significant bit
    -- is a flag:
    --            1 - the following byte should be included in this value
    --            0 - this is the last byte in the value
    --
    -- For example:
    --         0x8B     0x54
    --     10001011 01010100
    --      0001011  1010100
    --        00010111010100
    --                  1492
    --
    -- Some vint's are little endian.  Var "le" expects a boolean value,
    -- defaulting to false.
    local valBytes = {}
    local val = 0
    local loopControl
    repeat
        loopControl = 0
        local tempByte = payload:uint8(position)
        if tempByte then
            position = position + 1
            if tempByte >= 128 then
                tempByte = tempByte - 128
                loopControl = 1
            else
                loopControl = 2
            end
            table.insert(valBytes, tempByte)
        end
    until loopControl ~= 1
    if loopControl ~= 2 then
        return
    end
    -- convert the table into a number
    if le then
        local tempTable = {}
        for i = #valBytes, 1, -1 do
            table.insert(tempTable, valBytes[i])
        end
        valBytes = tempTable
    end
    local numShifts = #valBytes - 1
    for i,j in ipairs(valBytes) do
        val = bit.bor(val, bit.lshift(j, numShifts * 7))
        numShifts = numShifts - 1
    end
    return val, position
end

function rar:vintSkip(payload, position)
    -- for when we don't need the value, just to get past it
    local loopControl
    repeat
        loopControl = 0
        local tempByte = payload:uint8(position)
        if tempByte then
            position = position + 1
            if tempByte >= 128 then
                loopControl = 1
            else
                loopControl = 2
            end
        end
    until loopControl ~= 1
    if loopControl == 2 then
        return position
    end
end

function rar:v5(token, first, last)
    local status, error = pcall(function(token, first, last)
        -- don't know how much we'll need, so get a chunk of 16 bytes
        -- first four bytes are a CRC, so don't bother with them
        local payload = nw.getPayload(last + 5, last + 20)
        if payload then
            local position = 1
            local streamPosition = last + 5
            -- Get header length
            local headerLength, position = self:vintRead(payload, position)
            if headerLength and position then
                local headerType = payload:uint8(position)
                if headerType then
                    if headerType > 5 then
                        -- invalid, probably not a rar
                        return
                    end
                    nw.createMeta(self.keys.filetype, "rar")
                    if headerType == 4 then
                        -- encrypted
                        nw.createMeta(self.keys["alert.id"], alerts["encrypted"])
                        return
                    end
                    if headerType == 1 then
                        -- skip to end of header, as well as skipping the CRC (4 bytes) for the next header
                        streamPosition = last + 6 + headerLength + 4
                        -- loop through remainder of headers
                        repeat
                            local loopControl = 0
                            payload = nw.getPayload(streamPosition, streamPosition + 63)
                            local position = 1
                            local headerLength, position = self:vintRead(payload, position)
                            if headerLength and position then
                                -- update overall position in the stream with the end of this
                                -- block, as well as skipping the CRC32 of the next header
                                streamPosition = streamPosition + headerLength + 5
                                local headerType = payload:uint8(position)
                                if headerType then
                                    position = position + 1
                                    if headerType == 2  or headerType ==3 then -- File header or Service header
                                        -- get flags
                                        local headerFlags = payload:uint8(position)
                                        if headerFlags then
                                            position = position + 1
                                            if bit.band(headerFlags, 1) == 1 then
                                                -- skip "extra size"
                                                position = self:vintSkip(payload, position)
                                                if not position then
                                                    return
                                                end
                                            end
                                            if bit.band(headerFlags, 2) == 2 then
                                                -- get data size, this is also the packed file size (little endian)
                                                local dataSize
                                                dataSize, position = self:vintRead(payload, position, true)
                                                if dataSize and position then
                                                    streamPosition = streamPosition + dataSize
                                                else
                                                    -- something went wrong
                                                    return
                                                end
                                            end
                                            if headerType == 2 then -- the rest isn't relevant to a service header
                                                -- get fileFlags
                                                local fileFlags = payload:uint8(position)
                                                if fileFlags then
                                                    position = position + 1
                                                    -- skip unpacked size
                                                    position = self:vintSkip(payload, position)
                                                    if not position then
                                                        return
                                                    end
                                                    -- skip attributes
                                                    position = self:vintSkip(payload, position)
                                                    if not position then
                                                        return
                                                    end
                                                    if bit.band(fileFlags, 2) == 2 then
                                                        -- skip mtime
                                                        position = position + 4
                                                    end
                                                    if bit.band(fileFlags, 4) == 4 then
                                                        -- skip crc
                                                        position = position + 4
                                                    end
                                                    -- skip compression
                                                    position = self:vintSkip(payload, position)
                                                    if not position then
                                                        return
                                                    end
                                                    -- skip OS
                                                    position = position + 1
                                                    -- get name length
                                                    local nameLength, position = self:vintRead(payload, position)
                                                    if nameLength and position then
                                                        local nameEnd = position + nameLength - 1
                                                        local archivedFilename = payload:tostring(position, nameEnd)
                                                        if archivedFilename then
                                                            local dir, file, ext = nwll.extractPathElements(archivedFilename)
                                                            if dir then
                                                                nw.createMeta(self.keys.directory, dir)
                                                            end
                                                            if file then
                                                                nw.createMeta(self.keys.filename, file)
                                                            end
                                                            if ext then
                                                                nw.createMeta(self.keys.extension, ext)
                                                            end
                                                            -- If extra area exists, check it for a file encryption record,
                                                            -- which indicates password protection.  There can be multiple
                                                            -- "extra" records, but only check the first.
                                                            if bit.band(headerFlags, 1) == 1 then
                                                                position = nameEnd + 2
                                                                local recordType = payload:uint8(position)
                                                                if recordType then
                                                                    if recordType == 1 then
                                                                        nw.createMeta(self.keys["alert.id"], alerts["password"])
                                                                    end
                                                                    loopControl = 1
                                                                end
                                                            else
                                                                -- no extra area, just loop again
                                                                loopControl = 1
                                                            end
                                                        end
                                                    end
                                                end
                                            else
                                                -- just loop again for a service header
                                                loopControl = 1
                                            end
                                        end
                                    end
                                end
                            end
                        until loopControl == 0
                    end
                end
            end
        end
    end, token, first, last)
    if not status and debugParser then
        nw.logFailure(error)
    end
end

function rar:base64(token, first)
    local status, error = pcall(function(first)
        local payload = nw.getPayload(first, first + 31)
        if payload and payload:len() == 32 then
            local header = payload:tostring(1, -1)
            header = nw.base64Decode(header)
            if header then
                local version = string.byte(header, 7, 7)
                if version == 0 then
                    -- v4
                    if string.byte(header, 10, 10) == 0x73 then
                        nw.createMeta(self.keys.filetype, "rar")
                        local tempByte2, tempByte1 = string.byte(header, 11, 12)
                        if tempByte2 and tempByte1 then
                            local headerFlags = bit.bor(bit.lshift(tempByte1, 8), tempByte2)
                            if bit.band(headerFlags, 128) == 128 then
                                nw.createMeta(self.keys["alert.id"], alerts["encrypted"])
                            end
                        end
                    end
                elseif version == 1 then
                    if string.byte(header, 8, 8) == 0 then
                        -- v5
                        local position = 13
                        while bit.band(string.byte(header, position, position), 128) == 128 do
                            position = position + 1
                        end
                        position = position +1
                        local headerType = string.byte(header, position, position)
                        if headerType <= 5 then
                            nw.createMeta(self.keys.filetype, "rar")
                            if headerType == 4 then
                                nw.createMeta(self.keys["alert.id"], alerts["encrypted"])
                            end
                        end
                    end
                end
            end
        end
    end, first)
    if not status and debugParser then
        nw.logFailure(error)
    end
end

rar:setCallbacks({
    ["\082\097\114\033\026\007\000"] = rar.v4,     -- x52 x61 x72 x21 x1a x07 x00
    ["\082\097\114\033\026\007\001\000"] = rar.v5, -- x52 x61 x72 x21 x1a x07 x01 x00
    ["^UmFyIRoH"] = rar.base64
})

return summary