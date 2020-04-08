local parserName = "nwll"
local parserVersion = "2018.09.10.1"

local parserDetails = [=[
Commonly used parser functions in lua.

This file itself is not a parser.
]=]

nw.logDebug(parserName .. " " .. parserVersion)

--[[
    ===========================================================================

                                NETWITNESS LUA LIBRARY

    ===========================================================================

    Provides commonly used lua functions so that parsers do not have
    to include them individually.

    IMPLEMENTATION NOTES

        !!! DON'T TRY TO REGISTER META WITHIN THESE FUNCTIONS !!!

        Meta keys are not defined in this file, so registering meta directly from
        here won't work.  Instead, return the values that should be registered and
        have the parser which called the function perform the registration.


    ===========================================================================
    ===========================================================================
--]]

local string = require('string')
local bit = require('bit')
local table = require('table')
local tonumber = tonumber
local type = type
local ipairs = ipairs
local pairs = pairs
local math = require('math')
local nwpayload = nwpayload
local pcall = pcall
--local logDebug = nw.logDebug
--local logInfo = nw.logInfo
--local debugParser = require('debugParser')
--local print = print

module("nwll")

--[[                -------------------
                    DETERMINE HOST TYPE
                    -------------------

2016.07.11.2  wm  Completely rewritten.  Much better IPv6 validation
2016.03.21.1  wm  Truncate at forward slash
2015.09.01.1  wm  Use string.gmatch instead of looping string.find
2014.12.11.1  wm  Return nil for empty strings
2013.02.26.1  wm  Detect malformed IPv6
2012.10.04.1  wm  Use constructor to initialize table "dot"
2012.10.02.1  wm  Localize global functions
2012.08.13.1  wm  Use "alias.ip" not "alias.ipv4"
2012.07.23.1  wm  Initial development

Function which determines if a host is a hostname, IPv4, or IPv6.

Will strip any port specification.  For example:
    www.example.com:80 -> www.example.com

Will strip any brackets.  For example:
    [1.2.3.4] -> 1.2.3.4

Expects a string of the host.

Returns two (or three) values:

    1) the hostname or IP address stripped of any colons and brackets

    2) the type of host (alias.host, alias.ip, or alias.ipv6) which
       can be used directly in nw.createMeta
    
Example:  1.2.3.4:80 would return

    1.2.3.4    alias.ip

    which could be used as follows:

        host, key = nwll.determineHostType(host)
        if host and key then
            nw.createMeta(self.keys[key], host)
        end

--]]
function determineHostType(host)
    if not host or type(host) ~= "string" or #host == 0 then
        return
    end
    -- remove leading spaces
    host = string.match(host, "^%s+(.*)") or host
    -- truncate at first non-printable, space, or forward-slash
    host = string.match(host, "^([^%c%s/]+)") or host
    -- de-encapsulate from brackets if present
    host = string.match(host, "^%[([^%]]+)") or host
    -- strip port if present
    host = string.match(host, "^([^:]+):([^:]+)$") or host
    -- make sure we still have a string
    if #host == 0 then
        return
    end
    -- default to alias.host
    local key = "alias.host"
    local function isIPv4(host)
        if
            #host >= 7                              -- at least 7 characters
            and #host <= 15                         -- at most 15 characters
            and not string.find(host, "^.-[^%d%.]") -- only digits and dots
            and not string.find(host, "^.-%.%.")    -- no consecutive dots
        then
            local numOctets, fail = 0, false
            for octet in string.gmatch(host, "[^%.]+") do
                numOctets = numOctets + 1
                if numOctets == 5 then                -- no more than 4 octets (3 dots)
                    return false
                end
                if #octet > 3 then
                    return false                    -- no more than 3 characters
                end
                octet = tonumber(octet)
                if not octet or octet > 255 then        -- each octet must be a number 0-255
                    return false
                end
            end
            if numOctets == 4 then
                return true
            end
        end
        return false
    end
    -- Is it an IPv4?
    if isIPv4(host) then
        key = "alias.ip"
    elseif
        -- not IPv4, check if IPv6
        #host <= 46                                 -- no longer than 46 characters
        and string.find(host, "^.-:")               -- must contain colons
        and not string.find(host, "^.-[^%x:%.]")    -- must contain only colons, dots, and hex characters
        and not string.find(host, "^:[^:]")         -- must not lead with a single colon (double is okay)
        and not string.find(host, "[^:]:$")         -- must not end with a single colon (double is okay)
        and not string.find(host, "^.-:::")         -- must not be three or more consecutive colons
        and not string.find(host, "^.-%..-:")       -- no colons after a dot
    then
        local numColons, colonPairs = 0, 0
        for colon in string.gmatch(host, ":") do
            numColons = numColons + 1
        end
        for colonPair in string.gmatch(host, "::") do
            colonPairs = colonPairs + 1
        end
        if
            -- seven colons with no colons pairs
            (numColons == 7 and colonPairs == 0)
            -- two to seven colons with one colon pair
            or (numColons >= 2 and numColons <= 7 and colonPairs == 1)
            -- six colons with no colon pairs if dots follow last colon
            or (numColons == 6 and colonPairs == 0 and string.find(host, "^.-:.-%."))
            -- eight colons with one colon pair only if begins or ends with the colon pair
            or (numColons == 8 and colonPairs == 1 and (string.find(host, "^::") or string.find(host, "::$")))
        then
            local fields = {}
            for field in string.gmatch(host, "[^:]+") do
                table.insert(fields, field)
            end
            if #fields <= 8 then
                local fail
                for idx, field in ipairs(fields) do
                    -- at most 4 characters with no dots
                    if #field > 4 or string.find(field, "^.-%.") then
                        -- unless last two sections combined are an IPv4
                        if
                            #fields > 7                                                         -- no more than 7 fields
                            or (#fields == 7 and colonPairs == 1)                               -- no colon pair if 7 fields
                            or (#fields < 7 and colonPairs ~= 1)                                -- if less than 7 fields then colon pair must exist
                            or (string.find(field, "^0") or string.find(field, "^.-%.0[^%.]"))  -- no leading zeros
                            or not isIPv4(field)                                                -- must be a valid IPv4
                        then
                            fail = true
                            break
                        end
                    end
                end
                if not fail then
                    -- If passed all of the above, then is IPv6
                    key = "alias.ipv6"
                end
            end
        end
    end
    return host, key
end

--[[
                   -----------------------
                          URLDECODE
                   -----------------------

2013.11.07.1  wm  Initial development

Repurposed from the lua users string recipies wiki:

    http://lua-users.org/wiki/StringRecipes

Expects a string to be decoded.  Returns the decoded string.

Example:

    local encodedString = payload:tostring(postion, position + length)
    if encodedString then
        local decodedString = nwll.urldecode(tmpStr)
        ...

--]]
function urldecode(str)
    str = string.gsub(str, "+", " ")
    str = string.gsub(str, "%%(%x%x)", function(h) return string.char(tonumber(h,16)) end)
    str = string.gsub(str, "\r\n", "\n")
    return str
end

--[[               ---------------------
                   EXTRACT PATH ELEMENTS
                   ---------------------

2018.02.12.1  wm  tweak extension
2017.07.14.1  wm  accomodate escaped forward slashes
2016.04.07.1  wm  Use string.match
2015.09.01.1  wm  Complete rewrite
2014.12.11.1  wm  Return nil for empty strings
2013.02.27.1  wm  If length of fullpath is 0 then don't bother
2012.10.04.1  wm  Bugfix: set lastPosition to nil before extracting extension
2012.10.02.1  wm  Localize global functions
2012.07.28.1  wm  Initial development

Function which separates the directory, filename, and
extension from a given path.

Accomodates both forward slash (unix-style) and backslash
(windows-style) directory delimiters.

Returns three values, in this order:

    1) full directory path (not including filename)
    2) filename
    3) extension

Example:

    Given

        /path/to/some/file.name

    Returns

        /path/to/some/    file.name    name

Known limitations:

    If a path does not end with a slash, it is assumed that
    the last element of the path is a filename:

        "/this/is/my/directory"
        
        "directory" would be assumed to be a filename
        
    The alternative would be to assume that an ending path
    element that doesn't contain a dot is a directory, which
    is less likely to be correct.

--]]
function extractPathElements(fullpath)
    if not fullpath or type(fullpath) ~= "string" or string.len(fullpath) == 0 then
        return
    end
    -- truncate at first nonprintable
    local endOfLine = string.find(fullpath, "%c")
    if endOfLine then
        fullpath = string.sub(fullpath, 1, endOfLine - 1)
    end
    local directory, filename, extension
    if string.find(fullpath, "^.*[/\\]") then
        directory, filename = string.match(fullpath, "^(.*[/\\]+)(.*)")
    else
        filename = fullpath
    end
    directory = (directory and string.len(directory) ~= 0 and directory) or nil
    filename = (filename and string.len(filename) ~= 0 and filename) or nil
    if filename then
        local extTemp = {}
        local extBegin
        for ext in string.gmatch(filename, "[^%.]+") do
            table.insert(extTemp, ext)
        end
        if #extTemp > 1 then
            if #extTemp[#extTemp] <= 4 then
                extBegin = #extTemp
                for i = #extTemp - 1, 2, -1 do
                    if #extTemp[i] <= 3 then
                        extBegin = extBegin - 1
                    else
                        break
                    end
                end
            end
        end
        if extBegin then
            extension = table.concat(extTemp, ".", extBegin, #extTemp)        
        end
    end
    extension = (extension and string.len(extension) ~= 0 and extension) or nil
    return directory, filename, extension
end

--[[               --------------------
                   EXTRACT URL ELEMENTS
                   --------------------

2018.04.18.1  wm  try to extract host even if no schema is present
2018.04.12.1  wm  if no forward slash, assume host
2018.02.21.1  wm  rewrite to better handle non-compliant urls (primarily from web apps)
2017.07.14.1  wm  accomodate escaped forward slashes
2017.04.27.1  wm  accomodate .js weirdness
2016.10.31.1  wm  accomodate # as a path termination
2016.01.04.1  wm  accomodate ; as a querystring separator
2015.09.01.1  wm  truncate at first unprintable
                  extractPathElements() returns nil for empty string, no need to check here
2015.03.19.1  wm  Run though urldecode() after querystring is extracted
2014.12.11.1  wm  Return nil for empty strings
2014.11.12.1  wm  Make sure URI doesn't appear too far into URL
2014.02.14.1  wm  Rework (again) to accomodate colons in filenames (*sigh*)
2013.10.29.3  wm  Rework separation of host from path
2013.10.17.1  wm  Bugfix: urlQuery -> urlQuerystring
2013.06.14.1  wm  Initial development

Breaks out a url into host, directory, filename, extension, and querystring.

Expects a lua string, NOT payload!  (todo?)

Returns values similarly to extractPathElements().

IMPORTANT:  the "host" value returned must still be sent through determineHostType()

Example:

    local someURL = payload:tostring(x, y)
    local host, directory, filename, extension, querystring = nwll.extractUrlElements(someURL)
    if host then
        local key
        host, key = nwll.determineHostType(host)
        if host and key then
            nw.createMeta(self.keys[key], host)
        end
    end
    if directory then
        nw.createMeta(self.keys.directory, directory)
    end
    if filename then
        nw.createMeta(self.keys.filename, filename)
    end
    if extension then
        nw.createMeta(self.keys.extension, extension)
    end
    if querystring then
        nw.createMeta(self.keys.query, querystring)
    end
    
Reference: https://tools.ietf.org/html/rfc3986#section-3.4

--]]

function extractUrlElements(url)
    if not url then
        return
    end
    local stringFind = string.find
    -- truncate at unprintable, whitespace or quotation
    local found = string.find(url, "[%c%s\'\"]", 1)
    if found then
        url = string.sub(url, 1, found - 1)
    end
    if #url == 0 then
        return
    end
    local stringMatch = string.match
    local stringSub = string.sub
    local stringGsub = string.gsub
    local path, queryindicator, host, directory, filename, extension, querystring
    url = string.gsub(url, [=[\/]=], "/")
    -- trim schema if present (e.g., "http://")
    if stringFind(url, "^[%w%.]+:\\?/\\?/.*") then
        host, url = stringMatch(url, "^[%w%.]+:\\?/\\?/([^/]+)(/?.*)")
    elseif stringFind(url, "^.*/") then
        host, url = stringMatch(url, "^([^/]-)(/.*)$")
    else
        -- No schema, no slash, doesn't look like a url.  Since there's no way to tell
        -- if it is a host or file, assume it's a host - that'll be correct more
        -- often than not.
        return url
    end
    if url and #url > 0 then
        --  Separate "path" from querystring: path is a temporary value holding
        --  everything up to the first "special" character.
        --
        --  Special characters: ? # & : = ;
        path, queryindicator, querystring = stringMatch(url, "^([^%^?^#^&^:^=^;]+)([%?#&:=;])(.*)$")
        if not path then
            path = url
        end
        if not queryindicator or (queryindicator ~= "?" and queryindicator ~= "#") then
            -- Per RFC 3986 the only valid querystring indicators are ? and #, so either
            -- there really is no querystring, or this is something non-standard.  There
            -- appears to be no bounds to the degree of disdain some web app developers
            -- have for standards and interoperability - but do our best to attempt to
            -- infer intention.
            local lastSlash = stringFind(path, "/[^/]-$")
            if lastSlash then
                if not stringFind(path, "^.*%a", lastSlash) then
                    -- No letters after the last slash in path.  Consider querystring to be everything after the last slash
                    path = stringSub(url, 1, lastSlash)
                    querystring = stringSub(url, lastSlash + 1)
                else
                    local lastDot = stringFind(path, "%.[^%.]+$", lastSlash)
                    if not lastDot then
                        if queryindicator then
                            -- No dot after the last "/" in path - everything after the last "/" in the url is probably querystring
                            path = stringSub(url, 1, lastSlash)
                            querystring = stringSub(url, lastSlash + 1)
                        end
                    elseif not stringFind(path, "^.*%a", lastDot) then
                        -- No letters after the last dot in path.  Consider querystring to be everything after the last slash
                        path = stringSub(url, 1, lastSlash)
                        querystring = stringSub(url, lastSlash + 1)
                    elseif #path - lastDot > 4 then
                        -- More than 4 characters after the last dot in path.  Try to figure out where something
                        -- that might be an extension ends by looking for the last sequence of four-or-less
                        -- characters between dots.
                        local extEnd = 1
                        repeat
                            local _extEnd = stringFind(path, "%.[^%.][^%.][^%.][^%.]+", extEnd + 1)
                            if _extEnd then
                                extEnd = _extEnd
                            end
                        until not _extEnd
                        if extEnd ~= 1 then
                            path = stringSub(url, 1, extEnd - 1)
                            querystring = stringSub(url, extEnd, -1)
                        else
                            path = stringSub(url, 1, lastSlash)
                            querystring = stringSub(url, lastSlash + 1, -1)
                        end
                    end
                end
            end
        end
    end
    directory, filename, extension = extractPathElements(path)
    host = ((host and #host > 0) and host) or nil
    directory = ((directory and #directory > 0) and directory) or nil
    filename = ((filename and #filename > 0) and filename) or nil
    extension = ((extension and #extension > 0) and extension) or nil
    querystring = ((querystring and #querystring > 0) and querystring) or nil
    return host, directory, filename, extension, querystring
end

--[[               ------------------------
                   READ ASN.1 LENGTH VALUES
                   ------------------------

2013.11.06.1  wm  Support string as well as payload
2013.02.22.1  wm  Initial development - split from decodeASN()

Reads ASN.1 length values.

If the length byte is 127 or less, then that value itself specifies the length.
However, if a length byte is 128 or more, then the least-significant 7 bits
specifies the number of following bytes from which to read the length.

For example:

     a) length = 0x21 -> the length is 33

     b) length = 0x82 -> the next two bytes are the length

        0x82 = 130 = 10000010 -> 0000010 = 2
        (an easy way to do the same thing is to subtract 128: 130 - 128 = 2)

        So if the next two bytes were 0x0101, then the actual length is 257

--]]
function readASNlength(payload, position)
    if not (payload and position) then
        return
    end
    local nwuint8, nwuint16, nwuint32 = nwpayload.uint8, nwpayload.uint16, nwpayload.uint32
    if type(payload) == "string" then
        nwuint8 = string.byte
        nwuint16 = function(payload, position)
                -- doesn't support little-endian or multiple return values (todo?)
                local tempByte1 = string.byte(payload, position)
                local tempByte2 = string.byte(payload, position + 1)
                if tempByte1 and tempByte2 then
                    return bit.bor(bit.lshift(tempByte1, 8), tempByte2)
                end
            end
        nwuint32 = function(payload, position)
                -- doesn't support little-endian or multiple return values (todo?)
                local tempByte1 = string.byte(payload, position)
                local tempByte2 = string.byte(payload, position + 1)
                local tempByte3 = string.byte(payload, position + 2)
                local tempByte4 = string.byte(payload, position + 3)
                if tempByte1 and tempByte2 and tempByte3 and tempByte4 then
                    local tempShort1 = bit.bor(bit.lshift(tempByte1, 24), bit.lshift(tempByte2, 16))
                    local tempShort2 = bit.bor(bit.lshift(tempByte3, 8), tempByte4)
                    return bit.bor(tempShort1, tempShort2)
                end
            end
    end
    local length = nwuint8(payload, position)
    if length then
        position = position + 1
        if length > 128 then
            local lengthBytes = length - 128
            length = nil
            if lengthBytes == 1 then
                length = nwuint8(payload, position)
                position = position + 1
            elseif lengthBytes == 2 then
                length = nwuint16(payload, position)
                position = position + 2
            elseif lengthBytes == 3 then
                local tempByte1 = nwuint8(payload, position)
                local tempByte2 = nwuint8(payload, position + 1)
                local tempByte3 = nwuint8(payload, position + 2)
                if tempByte1 and tempByte2 and tempByte3 then
                    local bitBor, bitLshift = bit.bor, bit.lshift
                    length = bitBor(bitLshift(tempByte1, 16), bitBor(bitLshift(tempByte2, 8), tempByte3))
                    position = position + 3
                end
            elseif lengthBytes == 4 then
                length = nwuint32(payload, position)
                position = position + 4
            -- if lengthBytes is greater than 4 we can't deal with a number that big or this isn't an ASN.1 length anway
            end
        end
        return length, position
    end
end

--[[               -----------------------
                   DECODE ASN.1 STRUCTURES
                   -----------------------

2018.09.10.1  wm  use nwtostring for int > 4 bytes instead of payload:tostring()
2017.10.23.1  wm  default nextByte to 0 in OID extraction
2017.09.19.1  wm  Refactor extraction of int > 4 digits
2013.11.06.1  wm  Support string as well as payload
                  Option to not strip non-printable characters from string types
2013.09.10.1  wm  Remove 8 byte limit for integers
2013.09.09.1  wm  Go back to returning a string for unknown simple type, but
                  limit to 255 characters (before stripping unprintable)
2013.08.14.1  wm  Use string.gsub, remove local function convertString()
                  Return empty string for simple types with null payload
                  Return unknown simple types as an empty string, not a 'converted' string.
2013.05.24.1  wm  Make sure a value is returned before inserting into table
2013.05.06.1  wm  Ensure hex values in an OID are 2 digits
2013.03.18.1  as  Decode and return OID
2013.03.15.1  wm  Return a hex representation of an int > 4 bytes
2013.03.07.1  wm  Return simple type "null" as an empty string.
2013.02.22.1  wm  Split readASNlength() into a separately exposed function
                  Use table.insert()
2013.02.20.2  wm  Added "type" index to tables and subtables
2013.02.17.1  wm  Initial development

Returns an ASN.1 structure as a lua table, or a single simple data type as a value.

The function expects to be passed a payload object and a position within the payload at which the
desired ASN value begins.  So it doesn't matter if the function is passed just the ASN structure
itself or the entire stream - however for clarity and efficiency best practice would be to pass
a payload object of just the ASN structure not the entire stream.

If position is omitted it will default to "1" - which is useful if the payload passed consists
solely of the ASN structure, but potentially disastrous otherwise if the payload is the entire
stream, so be careful with that.

If the ASN value is a constructed type such as a sequence, it will be returned as a table.  Further
constructed type values within the construction (such as a sequence consisting of sequences) will
be returned as sub-tables within the larger table.

    For example, given the ASN.1 structure:

        30 1D 30 0E 02 01 01 02 01 02 30 06 02 01 03 02 01 04 30 06 04 01 41 04 01 42 04 03 46 4F 4F

    which specifies:

        sequence: length 29
            sequence: length 14
                integer: length 1, value 1
                integer: length 1, value 2
                sequence: length 6
                    integer: length 1, value 3
                    integer: length 1, value 4
            sequence: length 6
                string: length 1, value "A"
                string: length 1, value "B"
            string: length 3, value "FOO"

    will return the table:

        ({
            ["type"] = 48,
            [1] = ({
                ["type"] = 48,
                [1] = 1,
                [2] = 2,
                [3] = ({
                    ["type"] = 48,
                    [1] = 3,
                    [2] = 4
                })
            }),
            [2] = ({
                ["type"] = 48,
                [1] = "A",
                [2] = "B"
            }),
            [3] = "FOO"
        })


If the ASN value is a simple type such as a string or integer, it will be returned as a single value.

    For example, given the ASN structure:

        02 02 01 01

    which specifies:

        integer: length 2
          value: 257

    will return:

        257

If the position passed is at the point of the beginning of a constructed type, then a table representing only
that constructed value is returned.

    For example, given the ASN structure and position:

        30 1D 30 0E 02 01 01 02 01 02 30 06 02 01 03 02 01 04 30 06 04 01 41 04 01 42 04 03 46 4F 4F
                                                              ^
                                                              position
    which specifies:

        sequence: length 6
            string: length 1
                value: "A"
            string: length 1
                value: "B"

    will return:

        ({
            ["type"] = 48,
            [1] = "A",
            [2] = "B"
        })

If the position passed is at the point of a simple value within an ASN.1 structure, then only that value is returned.

    For example, given the ASN structure and position:

        30 1D 30 0E 02 01 01 02 01 02 30 06 02 01 03 02 01 04 30 06 04 01 41 04 01 42 04 03 46 4F 4F
                                                                    ^
                                                                    position
    which specifies:

        string: length 1
            value: "A"

    will return:

        "A"

This is useful if you are only looking for a specific value or construct and know exactly where it is.

For each constructed type, which is returned as a table (or sub-table), you may determine the literal
ASN type by referring to the "type" index of the table.

For example, given the same ASN payload as above:

    ASNtable = decodeASN(ASNpayload, 1)
    print(ASNtable[1]["type"])      --> 48

The table may still be traversed safely with ipairs() since "type" is not a numeric index.  But if it
is traversed with pairs() then "type" will be iterated.

This is useful for things like LDAP messages.  LDAP message types are all ASN constructed values.  The
data type itself is the type of LDAP message (e.g., 0x60 = "bind request").  So in order to determine the
type of LDAP message, you can simply refer to the data type of the appropriate subtable.

The optional parameter "leaveUnprintable" expects a boolean value defaulting to false/nil.  If 'true',
then non-printable characters are not stripped from string types.

--]]
function decodeASN(payload, position, leaveUnprintable)
    if not payload then
        return
    end
    local nwlength, nwsub, nwtostring, nwuint8, nwuint16, nwuint32 = nwpayload.len, nwpayload.sub, nwpayload.tostring, nwpayload.uint8, nwpayload.uint16, nwpayload.uint32
    if type(payload) == "string" then
        -- TODO: define these higher so that other functions can use them?
        nwlength = string.len
        nwsub = string.sub
        nwtostring = string.sub
        nwuint8 = string.byte
        nwuint16 = function(payload, position)
                -- doesn't support little-endian or multiple return values (todo?)
                local tempByte1 = string.byte(payload, position)
                local tempByte2 = string.byte(payload, position + 1)
                if tempByte1 and tempByte2 then
                    return bit.bor(bit.lshift(tempByte1, 8), tempByte2)
                end
            end
        nwuint32 = function(payload, position)
                -- doesn't support little-endian or multiple return values (todo?)
                local tempByte1 = string.byte(payload, position)
                local tempByte2 = string.byte(payload, position + 1)
                local tempByte3 = string.byte(payload, position + 2)
                local tempByte4 = string.byte(payload, position + 3)
                if tempByte1 and tempByte2 and tempByte3 and tempByte4 then
                    local tempShort1 = bit.bor(bit.lshift(tempByte1, 24), bit.lshift(tempByte2, 16))
                    local tempShort2 = bit.bor(bit.lshift(tempByte3, 8), tempByte4)
                    return bit.bor(tempShort1, tempShort2)
                end
            end
    end
    local simpleASNtypes = ({
        -- Define the ASN.1 "simple" types that we know how to decode.  Any "simple" type
        -- not listed here is extracted as a string.
        [0x01] = -- boolean
            function(payload)
                if not payload then
                    return false
                end
                local tempByte = nwuint8(payload, 1)
                if tempByte == 0xFF then
                    do
                        return true
                    end
                else
                    return false
                end
            end,
        [0x02] = -- integer
            function(payload)
                if not payload then
                    return ""
                end
                local length = nwlength(payload)
                if length == 1 then
                    do
                        return nwuint8(payload, 1)
                    end
                elseif length == 2 then
                    do
                        return nwuint16(payload, 1)
                    end
                elseif length == 3 then
                    local tempByte1 = nwuint8(payload, 1)
                    local tempByte2 = nwuint8(payload, 2)
                    local tempByte3 = nwuint8(payload, 3)
                    if tempByte1 and tempByte2 and tempByte3 then
                        local bitBor, bitLshift = bit.bor, bit.lshift
                        return bitBor(bitLshift(tempByte1, 16), bitBor(bitLshift(tempByte2, 8), tempByte3))
                    end
                elseif length == 4 then
                    do
                        return nwuint32(payload, 1)
                    end
                else
                    -- Lua can't handle numbers bigger than 4 bytes, so return a hex representation instead.
                    local bigInt = nwtostring(payload, 1, -1)
                    local hexRep = {"0x"}
                    for curByte = 1, string.len(bigInt) do
                        local hexByte = string.sub(bit.tohex(string.byte(bigInt, curByte)), -2, -1)
                        hexRep[#hexRep + 1] = hexByte
                    end
                    if #hexRep > 1 then
                        return table.concat(hexRep)
                    end
                end
            end,
        [0x04] = -- string
            function(payload)
                if not payload then
                    return ""
                end
                local incString = nwtostring(payload, 1, -1)
                local outString
                if leaveUnprintable then
                    outString = incString
                else
                    outString = string.gsub(incString, "[^%w%p%s]", "")
                end
                return outString
            end,
        [0x05] = -- null
            function(payload)
                -- Not sure how to deal with this so just return an empty string
                return ""
            end,
        [0x06] = -- oid
            function(payload)
                if not payload then
                    return ""
                end
                local position = 1
                local OID
                local byte = nwuint8(payload, position)
                if byte then
                    -- The first byte "b" is decoded in two nodes
                    -- The first node -> floor(b/40)
                    -- The second node -> b%40
                    --OID = math.floor(byte/40) .. "." .. byte % 40
                    OID = {}
                    table.insert(OID, math.floor(byte/40))
                    table.insert(OID, ".")
                    table.insert(OID, byte % 40)
                    position = position + 1
                    byte = nwuint8(payload, position)
                    while byte do
                        --if byte < 128, decimal value goes directly into a node
                        --if byte > 128 then the value was initially encoded in 2 or more bytes (m bytes)
                        --to decode it apply the following formula
                        -- num = (byte[j] - 128) * 128 ^ i + (byte[j+1] - 128) * 128 ^ (i - 1) + ... + (byte[j+m] - 128) * 128 (i - m)
                        if byte < 128 then
                            --OID = OID .. "." .. byte
                            table.insert(OID, ".")
                            table.insert(OID, byte)
                        else
                            local bigNumber = {}
                            bigNumber[1] = byte - 128
                            position = position + 1
                            local nextByte = nwuint8(payload, position) or 0
                            while nextByte > 128 do
                                table.insert(bigNumber,1,nextByte - 128)
                                position = position + 1
                                nextByte = nwuint8(payload, position) or 0
                            end
                            local temp = 0
                            -- a byte that is less that 128, this byte and all of the previous one larger than 128 go into one node
                            for i=1,#bigNumber do
                                temp = temp + bigNumber[i] * 128 ^ i
                            end
                            temp = temp + nextByte
                            --OID = OID .. "." .. temp
                            table.insert(OID, ".")
                            table.insert(OID, temp)
                        end
                        position = position + 1
                        byte = nwuint8(payload, position)
                    end
                end
                if OID and type(OID) == "table" then
                    return table.concat(OID)
                else
                    return ""
                end
            end,
    })

    local function buildASNconstructed(payload)
        -- Position is the first byte of the construct after
        -- its length - which is also the type of the first
        -- data type in the construct.
        local position = 1
        local ASNconstruct = {}
        repeat
            local loopControl = 0
            -- Constructs are constructed of more data types.
            local ASNtype = nwuint8(payload, position)
            -- When we get to the end of this construct, this check will fail and the loop will end
            if ASNtype then
                position = position + 1
                local length
                length, position = readASNlength(payload, position)
                if length and position then
                    -- A constructed type will have the "32" bit set
                    if bit.band(ASNtype, 32) == 32 then
                        -- This is a constructed type - it will become a sub-table of this table.
                        local constructedTable = {}
                        constructedTable = buildASNconstructed(nwsub(payload, position, position + length - 1))
                        constructedTable["type"] = ASNtype
                        table.insert(ASNconstruct, constructedTable)
                    elseif simpleASNtypes[ASNtype] then
                        -- This is a simple type that we know how to decode so send it off for extraction
                        local ASNpayload = nwsub(payload, position, position + length - 1)
                        local ASNvalue = simpleASNtypes[ASNtype](ASNpayload)
                        if ASNvalue then
                            table.insert(ASNconstruct, ASNvalue)
                        end
                    else
                        -- otherwise just return a string limited to 255 characters
                        local truncatedLength = length
                        if truncatedLength > 255 then
                            truncatedLength = 255
                        end
                        local ASNPayload = nwsub(payload, position, position + truncatedLength - 1)
                        local ASNvalue = simpleASNtypes[4](ASNPayload)
                        if ASNvalue then
                            table.insert(ASNconstruct, ASNvalue)
                        end
                    end
                    position = position + length
                    loopControl = 1
                end
            end
        until loopControl == 0
        return ASNconstruct
    end

    -- If we weren't passed a position then default to "1"
    local position = position or 1
    -- First byte is the ASN data type of the value
    local ASNtype = nwuint8(payload, position)
    if ASNtype then
        position = position + 1
        local length
        -- Next byte(s) are length of the value
        length, position = readASNlength(payload, position)
        if length and position then
            -- A constructed type will have the "32" bit set
            if bit.band(ASNtype, 32) == 32 then
                -- This is a constructed type: build a table with it and return the table.
                do
                    local constructedTable = {}
                    constructedTable = buildASNconstructed(nwsub(payload, position, position + length - 1))
                    constructedTable["type"] = ASNtype
                    return constructedTable, position + length
                end
            else
                -- This is a simple type: just return the value.
                local ASNvalue
                if simpleASNtypes[ASNtype] then
                    -- we know how to decode this type: send it off for extraction
                    ASNvalue = simpleASNtypes[ASNtype](nwsub(payload, position, position + length - 1))
                else
                    -- otherwise just return a string limited to 255 characters
                    local truncatedLength = length
                    if truncatedLength > 255 then
                        truncatedLength = 255
                    end
                    local ASNPayload = nwsub(payload, position, position + truncatedLength - 1)
                    local ASNvalue = simpleASNtypes[4](ASNPayload)
                end
                if ASNvalue then
                    return ASNvalue, position + length
                end
            end
        end
    end
end

--[=[              ----------------------------
                   CHECK IF TABLE PATH IS VALID
                   ----------------------------

2016.05.04.1  wm  bugfix & refactor
2016.03.01.1  wm  split from extractKerberos() and expanded

Checks if the given element path is valid for the given table

Example:

    if nwll.checkTable(someTable, "[1][2][3]") then

Returns false if someTable[1] or someTable[1][2] or someTable[1][2][3]
doesn't exist, otherwise returns true.

--]=]
function checkTable(testTable, testIndex)
    local indexes = {}
    for idx in string.gmatch(testIndex, "(%w+)") do
        table.insert(indexes, idx)
    end
    for i,j in ipairs(indexes) do
        if type(testTable) == "table" then
            j = tonumber(j) or j
            if testTable[j] then
                testTable = testTable[j]
            else
                return false
            end
        else
            return false
        end
    end
    return true
end

--[[               -----------------------------------
                   EXTRACT META FROM KERBEROS MESSAGES
                   -----------------------------------

2018.05.17.1  wm  total rewrite
2016.03.01.1  wm  split checkTable() into an independently exposed function
2015.05.12.1  wm  remove pcalls from ASN table lookups
2013.12.04.1  wm  bugfix: if type(ASN) ~= table -> if type(ASN) ~= "table"
2013.06.03.1  wm  Error code is ASN[1][6][1] (not [1][5][1])
2013.05.23.1  wm  Return error meta "unknown" for unknown error codes
2013.04.26.1  wm  Wrap ASN table lookups in pcall
2013.04.25.1  wm  Bugfix - reference K5cryptoTypes lookup table for crypto meta extraction
2013.03.06.1  wm  Initial development

Many protocols utilize Kerberos for authentication.  If you can isolate the Kerberos portion
of the payload, then you can use this function to easily extract Kerberos-related meta.

The structure of a Kerberos message is ASN.1, so decodeASN() is used to extract all the
values from a Kerberos message.  This function then interprets those values.

This function expects a payload object of just the Kerberos message.  The first byte of the
object MUST be the first byte of the Kerberos message.

Meta is returned as a table:

    ({
        [1] = ({
            ["key"] = value
        }),
        [2] = ({
            ["key"] = value
        }),
    })

so that it can easily be registered:

    local k5meta = extractKerberos(kerberosPayload)
    if k5meta then
        for idx, metaItem in ipairs(k5meta) do
            for indexKey, metaValue in pairs(metaItem) do
                nw.createMeta(self[keys][indexKey], metaValue)
            end
        end
    end

You'll need the following index keys declared in your parser:

    nwlanguagekey.create("action"),
    nwlanguagekey.create("ad.username.src"),
    nwlanguagekey.create("ad.computer.src"),
    nwlanguagekey.create("ad.domain.src"),
    nwlanguagekey.create("ad.username.dst"),
    nwlanguagekey.create("ad.computer.dst"),
    nwlanguagekey.create("ad.domain.dst"),
    nwlanguagekey.create("crypto"),
    nwlanguagekey.create("error"),

--]]
function extractKerberos(payload)
    if not payload then
        return
    end
    local K5cryptoTypes = {
        [0x01] =   "des-cbc-crc",
        [0x02] =   "des-cbc-md4",
        [0x03] =   "des-cbc-md5",
        [0x05] =   "des3-cbc-md5",
        [0x07] =   "des3-cbc-sha1",
        [0x09] =   "dsaWithSHA1-CmsOID",
        [0x0a] =   "md5WithRSAEncryption-CmsOID",
        [0x0b] =   "sha1WithRSAEncryption-CmsOID",
        [0x0c] =   "rc2CBC-EnvOID",
        [0x0d] =   "rsaEncryption-EnvOID",
        [0x0e] =   "rsaES-OAEP-ENV-OID",
        [0x0f] =   "des-ede3-cbc-Env-OID",
        [0x10] =   "des3-cbc-sha1-kd",
        [0x11] =   "aes128-cts-hmac-sha1-96",
        [0x12] =   "aes256-cts-hmac-sha1-96",
        [0x17] =   "rc4-hmac",
        [0x18] =   "rc4-hmac-exp",
        [0xFF79] = "rc4-hmac-old-exp",
    }
    local K5errorCodes = {
        -- http://technet.microsoft.com/en-us/library/cc738673(v=ws.10).aspx
        [0x3] =  "KDC ERR BAD PVNO",
        [0x6] =  "KDC ERR C PRINCIPAL UNKNOWN",
        [0x7] =  "KDC ERR S PRINCIPAL UNKNOWN",
        [0x8] =  "KDC ERR PRINCIPAL NOT UNIQUE",
        [0xA] =  "KDC ERR CANNOT POSTDATE",
        [0xB] =  "KDC ERR NEVER VALID",
        [0xC] =  "KDC ERR POLICY",
        [0xD] =  "KDC ERR BADOPTION",
        [0xE] =  "KDC ERR ETYPE NOSUPP",
        [0xF] =  "KDC ERR SUMTYPE NOSUPP",
        [0x10] = "KDC ERR PADATA TYPE NOSUPP",
        [0x12] = "KDC ERR CLIENT REVOKED",
        [0x17] = "KDC ERR KEY EXPIRED",
        [0x18] = "KDC ERR PREAUTH FAILED",
        [0x19] = "KDC ERR PREAUTH REQUIRED",
        [0x1B] = "KDC ERR MUST USE USER2USER",
        [0x1C] = "KDC ERR PATH NOT ACCPETED",
        [0x1D] = "KDC ERR SVC UNAVAILABLE",
        [0x1F] = "KRB AP ERR BAD INTEGRITY",
        [0x20] = "KRB AP ERR TKT EXPIRED",
        [0x21] = "KRB AP ERR TKT NYV",
        [0x22] = "KRB AP ERR REPEAT",
        [0x23] = "KRB AP ERR NOT US",
        [0x24] = "KRB AP ERR BADMATCH",
        [0x25] = "KRB AP ERR SKEW",
        [0x28] = "KRB AP ERR MSG TYPE",
        [0x29] = "KRB AP ERR MODIFIED",
        [0x34] = "KRB ERR RESPONSE TOO BIG",
        [0x3C] = "KRB ERR GENERIC",
        [0x44] = "KDC ERR WRONG REALM",
    }
    local K5nameTypes = {
        ["principal"] =
            function(ASN)
                if type(ASN) == "table"
                and ASN.type == 48
                and type(ASN[2]) == "table"
                and type(ASN[2][1]) == "table"
                then
                    local names = {}
                    for i,j in ipairs(ASN[2][1]) do
                        if type(j) == "string" then
                            table.insert(names, j)
                        end
                    end
                    return names
                end
            end,
        ["encryption"] =
            function(ASN)
                if type(ASN) == "table"
                and type(ASN[1]) == "table"
                and type(ASN[1][1]) == "table"
                then
                    return K5cryptoTypes[ASN[1][1][1]]
                end
            end,
        ["addresses"] =
            function(ASN)
                if type(ASN) == "table" then
                    local addresses = {}
                    for i,j in ipairs(ASN) do
                        if type(j) == "table"
                        and j.type == 48
                        and type(j[2]) == "table"
                        and type(j[2][1]) == "string"
                        then
                            table.insert(addresses, j[2][1])
                        end
                    end
                    return addresses
                end
            end,
    }
    local K5functions = {
        [0x0A] = -- AS REQ (10) and TGS REQ (12)
            function(ASN)
                local meta = {}
                if ASN[1][2][1] == 0x0A then
                    -- AS REQ
                    table.insert(meta, {["action"] = "kerberos as request"})
                elseif ASN[1][2][1] == 0x0C then
                    -- TGS REQ
                    table.insert(meta, {["action"] = "kerberos tgs request"})
                end
                for i,ii in ipairs(ASN[1]) do
                    if type(ii) == "table" and ii.type == 164 and ii[1] and type(ii[1]) == "table" then
                        -- request body
                        for j, jj in ipairs(ii[1]) do
                            if type(jj) == "table" then
                                if jj.type == 161 then
                                    -- cname
                                    local names = K5nameTypes.principal(jj[1])
                                    if names then
                                        if names[1] then
                                            table.insert(meta, {["ad.username.src"] = names[1]})
                                        end
                                        if names[2] then
                                            table.insert(meta, {["ad.computer.src"] = names[2]})
                                        end
                                    end
                                elseif jj.type == 162 and type(jj[1]) == "string" then
                                    -- srealm
                                    table.insert(meta, {["ad.domain.dst"] = jj[1]})
                                elseif jj.type == 163 then
                                    -- sname
                                    local names = K5nameTypes.principal(jj[1])
                                    if names then
                                        if names[1] then
                                            table.insert(meta, {["ad.username.dst"] = names[1]})
                                        end
                                        if names[2] then
                                            table.insert(meta, {["ad.computer.dst"] = names[2]})
                                        end
                                    end
                                elseif jj.type == 169 then
                                    -- addresses
                                    --
                                    -- The RFC says, "... specifies the addresses from which the requested
                                    -- ticket is to be valid."
                                    --
                                    -- I'm unclear whether that means these are src or dst hosts.  I'm
                                    -- calling them dst.
                                    local addresses = K5nameTypes.addresses(jj[1])
                                    if addresses then
                                        for i,j in ipairs(addresses) do
                                            table.insert(meta, {["ad.computer.dst"] = j})
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
                return meta
            end,
        [0x0B] = -- AS REP (11) and TGS REP (13)
            function(ASN)
                local meta = {}
                if ASN[1][2][1] == 0x0B then
                    -- AS REP
                    table.insert(meta, {["action"] = "kerberos as reply"})
                elseif ASN[1][2][1] == 0x0D then
                    -- TGS REP
                    table.insert(meta, {["action"] = "kerberos tgs reply"})
                end
                for i,ii in ipairs(ASN[1]) do
                    if type(ii) == "table" then
                        if ii.type == 163 and type(ii[1]) == "string" then
                            -- crealm
                            table.insert(meta, {["ad.domain.src"] = ii[1]})
                        elseif ii.type == 164 and type(ii[1]) == "table" then
                            -- cname
                            local names = K5nameTypes.principal(ii[1])
                            if names then
                                if names[1] then
                                    table.insert(meta, {["ad.username.src"] = names[1]})
                                end
                                if names[2] then
                                    table.insert(meta, {["ad.computer.src"] = names[2]})
                                end
                            end
                        elseif ii.type == 165 then
                            -- ticket
                            if type(ii[1]) == "table"
                            and type(ii[1][1]) == "table"
                            then
                                for j,jj in ipairs(ii[1][1]) do
                                    if type(jj) == "table" then
                                        if jj.type == 161 and type(jj[1]) == "string" then
                                            -- srealm
                                            table.insert(meta, {["ad.domain.dst"] = jj[1]})
                                        elseif jj.type == 162 and type(jj[1]) == "table" then
                                            -- sname
                                            local names = K5nameTypes.principal(jj[1])
                                            if names then
                                                if names[1] then
                                                    table.insert(meta, {["ad.username.dst"] = names[1]})
                                                end
                                                if names[2] then
                                                    table.insert(meta, {["ad.computer.dst"] = names[2]})
                                                end
                                            end
                                        elseif jj.type == 163 then
                                            -- crypto
                                            local crypto = K5nameTypes.encryption(jj)
                                            if crypto then
                                                table.insert(meta, {["crypto"] = crypto})
                                            end
                                        end
                                    end
                                end
                            end
                        elseif ii.type == 166 then
                            -- crypto
                            local crypto = K5nameTypes.encryption(ii)
                            if crypto then
                                table.insert(meta, {["crypto"] = crypto})
                            end
                        end
                    end
                end
                return meta
            end,
        [0x0E] = -- AP REQ (14)
            function(ASN)
                local meta = {{["action"] = "kerberos ap request"}}
                for i, ii in ipairs(ASN[1]) do
                    if type(ii) == "table" and ii.type == 163 then
                        -- ticket
                        if type(ii[1]) == "table"
                        and type(ii[1][1]) == "table"
                        then
                            for j,jj in ipairs(ii[1][1]) do
                                if type(jj) == "table" then
                                    if jj.type == 161 and type(jj[1]) == "string" then
                                        -- srealm
                                        table.insert(meta, {["ad.domain.dst"] = jj[1]})
                                    elseif jj.type == 162 and type(jj[1]) == "table" then
                                        -- sname
                                        local names = K5nameTypes.principal(jj[1])
                                        if names then
                                            if names[1] then
                                                table.insert(meta, {["ad.username.dst"] = names[1]})
                                            end
                                            if names[2] then
                                                table.insert(meta, {["ad.computer.dst"] = names[2]})
                                            end
                                        end
                                    elseif jj.type == 163 then
                                        -- crypto
                                        local crypto = K5nameTypes.encryption(jj)
                                        if crypto then
                                            table.insert(meta, {["crypto"] = crypto})
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
                return meta
            end,
        [0x1E] = -- ERROR (30)
            function(ASN)
                local meta = {}
                for i,ii in ipairs(ASN[1]) do
                    if type(ii) == "table" then
                        if ii.type == 166 then
                            -- error code
                            if K5errorCodes[ii[1]] then
                                table.insert(meta, {["error"] = K5errorCodes[ii[1]]})
                            else
                                table.insert(meta, {["error"] = "unknown"})
                            end
                        elseif ii.type == 167 and type(ii[1]) == "string" then
                            -- crealm
                            table.insert(meta, {["ad.domain.src"] = ii[1]})
                        elseif ii.type == 168 and type(ii[1]) == "table" then
                            -- cname
                            local names = K5nameTypes.principal(ii[1])
                            if names then
                                if names[1] then
                                    table.insert(meta, {["ad.username.src"] = names[1]})
                                end
                                if names[2] then
                                    table.insert(meta, {["ad.computer.src"] = names[2]})
                                end
                            end
                        elseif ii.type == 169 and type(ii[1]) == "string" then
                            -- srealm
                            table.insert(meta, {["ad.domain.dst"] = ii[1]})
                        elseif ii.type == 170 and type(ii[1]) == "table" then
                            -- sname
                            local names = K5nameTypes.principal(ii[1])
                            if names then
                                if names[1] then
                                    table.insert(meta, {["ad.username.dst"] = names[1]})
                                end
                                if names[2] then
                                    table.insert(meta, {["ad.computer.dst"] = names[2]})
                                end
                            end
                        end
                    end
                end
                return meta
            end,
        --[=[  Other message types not parsed - nothing useful to extract
        [0x0F] = "kerberos AP reply"
        [0x14] = "kerberos SAFE message",
        [0x15] = "kerberos PRIV message",
        [0x16] = "kerberos CRED message",
        --]=]
    }
    K5functions[0x0C] = K5functions[0x0A] -- a TGS request is identical to an AS request
    K5functions[0x0D] = K5functions[0x0B] -- a TGS reponse is identical to an AS response
    local ASN
    if type(payload) == "table" then
        ASN = payload
    else
        ASN = decodeASN(payload)
        if not ASN or type(ASN) ~= "table" then
            return
        end
    end
    if type(ASN[1]) == "table" and type(ASN[1][2]) == "table" then
        local messageType = ASN[1][2][1]
        if K5functions[messageType] then
            return K5functions[messageType](ASN)
        end
    end
end

--[[               -----------------------
                   DECODE QUOTED PRINTABLE
                   -----------------------

2015.09.01.1  wm  Convert payload to string
2014.03.21.1  wm  Support decoding strings (not just payload)
2013.04.19.1  wm  Initial development

Expects a payload object or string to be decoded from "quoted-printable".

If payload, then the first byte of the payload object must be the first
character of the encoded string.

Returns a decoded lua string.

Example:

    local encodedString = payload:sub(i, j)
    if encodedString then
        local decodedString = nwll.decodeQuotedPrintable(encodedString)
        if decodedString then
            ...
        end
    end

--]]

function decodeQuotedPrintable(encodedString)
    if not encodedString then
        return
    end
    if type(encodedString) == "userdata" then
        encodedString = nwpayload.tostring(encodedString)
    end
    local decodedString = string.gsub(encodedString, "=%x%x", function(hexChar)
                                                                  hexChar = string.gsub(hexChar, "=", "0x")
                                                                  return string.char(hexChar)
                                                              end
                                     )
    return decodedString
end

--[[               --------------
                   CONVERT EBCDIC
                   --------------

2013.04.22.1  wm  Initial development

Replicates the flex function <convert-ebcdic .../>

Expects to be passed two values:

    1)  A payload object consisting solely of EBCDIC characters.  The first byte
        of the payload object must be the first EBCDIC character.

    2)  The name of an EBCDIC code page from which to convert to ASCII.  If omitted, then
        "500" is assumed.

Currently only EBCDIC 500 is supported.

Returns a lua string.  Any control characters are stripped.

Example:

    local payloadEBCDIC = payload:sub(position, position + length)
    local asciiString = nwll.convertEBCDIC(payloadEBCDIC, "500")

--]]

function convertEBCDIC(payload, codePage)
    if not payload then
        return
    end
    local EBCDIC2ASCII
    if not codePage or codePage == "500" then
        EBCDIC2ASCII = ({
            ["\000"] = "",
            ["\001"] = "",
            ["\002"] = "",
            ["\003"] = "",
            ["\004"] = "",
            ["\005"] = "",
            ["\006"] = "",
            ["\007"] = "",
            ["\008"] = "",
            ["\009"] = "",
            ["\010"] = "",
            ["\011"] = "",
            ["\012"] = "",
            ["\013"] = "",
            ["\014"] = "",
            ["\015"] = "",
            ["\016"] = "",
            ["\017"] = "",
            ["\018"] = "",
            ["\019"] = "",
            ["\020"] = "",
            ["\021"] = "",
            ["\022"] = "",
            ["\023"] = "",
            ["\024"] = "",
            ["\025"] = "",
            ["\026"] = "",
            ["\027"] = "",
            ["\028"] = "",
            ["\029"] = "",
            ["\030"] = "",
            ["\031"] = "",
            ["\032"] = "",
            ["\033"] = "",
            ["\034"] = "",
            ["\035"] = "",
            ["\036"] = "",
            ["\037"] = "",
            ["\038"] = "",
            ["\039"] = "",
            ["\040"] = "",
            ["\041"] = "",
            ["\042"] = "",
            ["\043"] = "",
            ["\044"] = "",
            ["\045"] = "",
            ["\046"] = "",
            ["\047"] = "",
            ["\048"] = "",
            ["\049"] = "",
            ["\050"] = "",
            ["\051"] = "",
            ["\052"] = "",
            ["\053"] = "",
            ["\054"] = "",
            ["\055"] = "",
            ["\056"] = "",
            ["\057"] = "",
            ["\058"] = "",
            ["\059"] = "",
            ["\060"] = "",
            ["\061"] = "",
            ["\062"] = "",
            ["\063"] = "",
            ["\064"] = " ",
            ["\065"] = "",
            ["\066"] = "â",
            ["\067"] = "ä",
            ["\068"] = "à",
            ["\069"] = "á",
            ["\070"] = "ã",
            ["\071"] = "å",
            ["\072"] = "ç",
            ["\073"] = "ñ",
            ["\074"] = "[",
            ["\075"] = ".",
            ["\076"] = "<",
            ["\077"] = "(",
            ["\078"] = "+",
            ["\079"] = "!",
            ["\080"] = "&",
            ["\081"] = "é",
            ["\082"] = "ê",
            ["\083"] = "ë",
            ["\084"] = "è",
            ["\085"] = "í",
            ["\086"] = "î",
            ["\087"] = "ï",
            ["\088"] = "ì",
            ["\089"] = "ß",
            ["\090"] = "]",
            ["\091"] = "$",
            ["\092"] = "*",
            ["\093"] = ")",
            ["\094"] = ";",
            ["\095"] = "^",
            ["\096"] = "-",
            ["\097"] = "/",
            ["\098"] = "Â",
            ["\099"] = "Ä",
            ["\100"] = "À",
            ["\101"] = "Á",
            ["\102"] = "Ã",
            ["\103"] = "Å",
            ["\104"] = "Ç",
            ["\105"] = "Ñ",
            ["\106"] = "¦",
            ["\107"] = ",",
            ["\108"] = "%",
            ["\109"] = "_",
            ["\110"] = ">",
            ["\111"] = "?",
            ["\112"] = "ø",
            ["\113"] = "É",
            ["\114"] = "Ê",
            ["\115"] = "Ë",
            ["\116"] = "È",
            ["\117"] = "Í",
            ["\118"] = "Î",
            ["\119"] = "Ï",
            ["\120"] = "Ì",
            ["\121"] = "`",
            ["\122"] = ":",
            ["\123"] = "#",
            ["\124"] = "@",
            ["\125"] = "'",
            ["\126"] = "=",
            ["\127"] = '"',
            ["\128"] = "Ø",
            ["\129"] = "a",
            ["\130"] = "b",
            ["\131"] = "c",
            ["\132"] = "d",
            ["\133"] = "e",
            ["\134"] = "f",
            ["\135"] = "g",
            ["\136"] = "h",
            ["\137"] = "i",
            ["\138"] = "«",
            ["\139"] = "»",
            ["\140"] = "ð",
            ["\141"] = "ý",
            ["\142"] = "þ",
            ["\143"] = "±",
            ["\144"] = "°",
            ["\145"] = "j",
            ["\146"] = "k",
            ["\147"] = "l",
            ["\148"] = "m",
            ["\149"] = "n",
            ["\150"] = "o",
            ["\151"] = "p",
            ["\152"] = "q",
            ["\153"] = "r",
            ["\154"] = "ª",
            ["\155"] = "º",
            ["\156"] = "æ",
            ["\157"] = "¸",
            ["\158"] = "Æ",
            ["\159"] = "¤",
            ["\160"] = "µ",
            ["\161"] = "~",
            ["\162"] = "s",
            ["\163"] = "t",
            ["\164"] = "u",
            ["\165"] = "v",
            ["\166"] = "w",
            ["\167"] = "x",
            ["\168"] = "y",
            ["\169"] = "z",
            ["\170"] = "¡",
            ["\171"] = "¿",
            ["\172"] = "Ð",
            ["\173"] = "Ý",
            ["\174"] = "Þ",
            ["\175"] = "®",
            ["\176"] = "¢",
            ["\177"] = "£",
            ["\178"] = "¥",
            ["\179"] = "·",
            ["\180"] = "©",
            ["\181"] = "§",
            ["\182"] = "¶",
            ["\183"] = "¼",
            ["\184"] = "½",
            ["\185"] = "¾",
            ["\186"] = "¬",
            ["\187"] = "|",
            ["\188"] = "¯",
            ["\189"] = "¨",
            ["\190"] = "´",
            ["\191"] = "×",
            ["\192"] = "{",
            ["\193"] = "A",
            ["\194"] = "B",
            ["\195"] = "C",
            ["\196"] = "D",
            ["\197"] = "E",
            ["\198"] = "F",
            ["\199"] = "G",
            ["\200"] = "H",
            ["\201"] = "I",
            ["\203"] = "ô",
            ["\204"] = "ö",
            ["\205"] = "ò",
            ["\206"] = "ó",
            ["\207"] = "õ",
            ["\208"] = "}",
            ["\209"] = "J",
            ["\210"] = "K",
            ["\211"] = "L",
            ["\212"] = "M",
            ["\213"] = "N",
            ["\214"] = "O",
            ["\215"] = "P",
            ["\216"] = "Q",
            ["\217"] = "R",
            ["\218"] = "¹",
            ["\219"] = "û",
            ["\220"] = "ü",
            ["\221"] = "ù",
            ["\222"] = "ú",
            ["\223"] = "ÿ",
            ["\224"] = "\\",
            ["\225"] = "÷",
            ["\226"] = "S",
            ["\227"] = "T",
            ["\228"] = "U",
            ["\229"] = "V",
            ["\230"] = "W",
            ["\231"] = "X",
            ["\232"] = "Y",
            ["\233"] = "Z",
            ["\234"] = "²",
            ["\235"] = "Ô",
            ["\236"] = "Ö",
            ["\237"] = "Ò",
            ["\238"] = "Ó",
            ["\239"] = "Õ",
            ["\240"] = "0",
            ["\241"] = "1",
            ["\242"] = "2",
            ["\243"] = "3",
            ["\244"] = "4",
            ["\245"] = "5",
            ["\246"] = "6",
            ["\247"] = "7",
            ["\248"] = "8",
            ["\249"] = "9",
            ["\250"] = "³",
            ["\251"] = "Û",
            ["\252"] = "Ü",
            ["\253"] = "Ù",
            ["\254"] = "Ú",
            ["\255"] = ""
        })
    end
    if EBCDIC2ASCII then -- if an invalid code page was passed, this check will fail
        local stringEBCDIC = nwpayload.tostring(payload, 1, -1)
        local stringASCCI = string.gsub(stringEBCDIC, ".", EBCDIC2ASCII)
        return stringASCCI
    end
end

--[[               --------------------
                   CALCULATE AN MD5 SUM
                   --------------------

    2013.10.01.1  REMOVED

--]]

--[[               -------------------
                   WINDOWS ERROR CODES
                   -------------------

2013.05.31.1  wm  Converted to big endian
2013.03.04.1  wm  Moved from smb.lua

NOTES

    According to the CIFS documentation:
        "This is not an exhaustive listing and MUST NOT be considered normative."

    Furthermore, each SMB/MSRPC/etc. command and subcommand may use different
    error codes.  Worse still, each server may return status codes from its
    underlying OS which are not listed here.

    So this is a "best effort"...

    Error values are cut-n-pasted directly from the documentation.  No attempt
    at interpretation has been made.

HOW TO USE THIS FUNCTION IN YOUR PARSER

    errorCodeTable = nwll.winErr()

    Best place is probably OnInit.  "errorCodeTable" would be populated with the
    values below, which you could then use by doing something like:

        local errorCode = payload:uint32(position)
        if errorCode and errorCodeTable[errorCode] then
            nw.createMeta(self.keys.error, errorCodeTable[errorCode])
--]]
function winErr()
    return ({
        -- this first set are errors which appear in MS-CIFS but not NT_STATUS (from MS-ERREF).
        [0x000C0001] = "OS2 INVALID ACCESS",
        [0x007C0001] = "OS2 INVALID LEVEL",
        [0x00830001] = "OS2 NEGATIVE SEEK",
        [0x00710001] = "OS2 NO MORE SIDS",
        [0x00AD0001] = "OS2 CANCEL VIOLATION",
        [0x00AE0001] = "OS2 ATOMIC LOCKS NOT SUPPORTED",
        [0x010A0001] = "OS2 CANNOT COPY",
        [0x01130001] = "OS2 EAS DIDNT FIT",
        [0x03E20001] = "OS2 EA ACCESS DENIED",
        [0x00050002] = "SMB BAD TID",
        [0x00160002] = "SMB BAD COMMAND",
        [0x005B0002] = "SMB BAD UID",
        [0x00FA0002] = "SMB USE MPX",
        [0x00FB0002] = "SMB USE STANDARD",
        [0x00FC0002] = "SMB CONTINUE MPX",
        [0xFFFF0002] = "SMB NO SUPPORT",
        -- this second set are NT_STATUS codes from MS-ERREF.
        [0x00000001] = "WAIT 1",
        [0x00000002] = "WAIT 2",
        [0x00000003] = "WAIT 3",
        [0x0000003F] = "WAIT 63",
        [0x00000080] = "ABANDONED",
        [0x00000080] = "ABANDONED WAIT 0",
        [0x000000BF] = "ABANDONED WAIT 63",
        [0x000000C0] = "USER APC",
        [0x00000101] = "ALERTED",
        [0x00000102] = "TIMEOUT",
        [0x00000103] = "PENDING",
        [0x00000104] = "REPARSE",
        [0x00000105] = "MORE ENTRIES",
        [0x00000106] = "NOT ALL ASSIGNED",
        [0x00000107] = "SOME NOT MAPPED",
        [0x00000108] = "OPLOCK BREAK IN PROGRESS",
        [0x00000109] = "VOLUME MOUNTED",
        [0x0000010A] = "RXACT COMMITTED",
        [0x0000010B] = "NOTIFY CLEANUP",
        [0x0000010C] = "NOTIFY ENUM DIR",
        [0x0000010D] = "NO QUOTAS FOR ACCOUNT",
        [0x0000010E] = "PRIMARY TRANSPORT CONNECT FAILED",
        [0x00000110] = "PAGE FAULT TRANSITION",
        [0x00000111] = "PAGE FAULT DEMAND ZERO",
        [0x00000112] = "PAGE FAULT COPY ON WRITE",
        [0x00000113] = "PAGE FAULT GUARD PAGE",
        [0x00000114] = "PAGE FAULT PAGING FILE",
        [0x00000115] = "CACHE PAGE LOCKED",
        [0x00000116] = "CRASH DUMP",
        [0x00000117] = "BUFFER ALL ZEROS",
        [0x00000118] = "REPARSE OBJECT",
        [0x00000119] = "RESOURCE REQUIREMENTS CHANGED",
        [0x00000120] = "TRANSLATION COMPLETE",
        [0x00000121] = "DS MEMBERSHIP EVALUATED LOCALLY",
        [0x50434C4C] = "PC LOAD LETTER",
        [0x00000122] = "NOTHING TO TERMINATE",
        [0x00000123] = "PROCESS NOT IN JOB",
        [0x00000124] = "PROCESS IN JOB",
        [0x00000125] = "VOLSNAP HIBERNATE READY",
        [0x00000126] = "FSFILTER OP COMPLETED SUCCESSFULLY",
        [0x00000127] = "INTERRUPT VECTOR ALREADY CONNECTED",
        [0x00000128] = "INTERRUPT STILL CONNECTED",
        [0x00000129] = "PROCESS CLONED",
        [0x0000012A] = "FILE LOCKED WITH ONLY READERS",
        [0x0000012B] = "FILE LOCKED WITH WRITERS",
        [0x00000202] = "RESOURCEMANAGER READ ONLY",
        [0x00000367] = "WAIT FOR OPLOCK",
        [0x00010001] = "DBG EXCEPTION HANDLED",
        [0x00010002] = "DBG CONTINUE",
        [0x001C0001] = "FLT IO COMPLETE",
        [0xC0000467] = "FILE NOT AVAILABLE",
        [0xC0000721] = "CALLBACK RETURNED THREAD AFFINITY",
        [0x40000000] = "OBJECT NAME EXISTS",
        [0x40000001] = "THREAD WAS SUSPENDED",
        [0x40000002] = "WORKING SET LIMIT RANGE",
        [0x40000003] = "IMAGE NOT AT BASE",
        [0x40000004] = "RXACT STATE CREATED",
        [0x40000005] = "SEGMENT NOTIFICATION",
        [0x40000006] = "LOCAL USER SESSION KEY",
        [0x40000007] = "BAD CURRENT DIRECTORY",
        [0x40000008] = "SERIAL MORE WRITES",
        [0x40000009] = "REGISTRY RECOVERED",
        [0x4000000A] = "FT READ RECOVERY FROM BACKUP",
        [0x4000000B] = "FT WRITE RECOVERY",
        [0x4000000C] = "SERIAL COUNTER TIMEOUT",
        [0x4000000D] = "NULL LM PASSWORD",
        [0x4000000E] = "IMAGE MACHINE TYPE MISMATCH",
        [0x4000000F] = "RECEIVE PARTIAL",
        [0x40000010] = "RECEIVE EXPEDITED",
        [0x40000011] = "RECEIVE PARTIAL EXPEDITED",
        [0x40000012] = "EVENT DONE",
        [0x40000013] = "EVENT PENDING",
        [0x40000014] = "CHECKING FILE SYSTEM",
        [0x40000015] = "FATAL APP EXIT",
        [0x40000016] = "PREDEFINED HANDLE",
        [0x40000017] = "WAS UNLOCKED",
        [0x40000018] = "SERVICE NOTIFICATION",
        [0x40000019] = "WAS LOCKED",
        [0x4000001A] = "LOG HARD ERROR",
        [0x4000001B] = "ALREADY WIN32",
        [0x4000001C] = "WX86 UNSIMULATE",
        [0x4000001D] = "WX86 CONTINUE",
        [0x4000001E] = "WX86 SINGLE STEP",
        [0x4000001F] = "WX86 BREAKPOINT",
        [0x40000020] = "WX86 EXCEPTION CONTINUE",
        [0x40000021] = "WX86 EXCEPTION LASTCHANCE",
        [0x40000022] = "WX86 EXCEPTION CHAIN",
        [0x40000023] = "IMAGE MACHINE TYPE MISMATCH EXE",
        [0x40000024] = "NO YIELD PERFORMED",
        [0x40000025] = "TIMER RESUME IGNORED",
        [0x40000026] = "ARBITRATION UNHANDLED",
        [0x40000027] = "CARDBUS NOT SUPPORTED",
        [0x40000028] = "WX86 CREATEWX86TIB",
        [0x40000029] = "MP PROCESSOR MISMATCH",
        [0x4000002A] = "HIBERNATED",
        [0x4000002B] = "RESUME HIBERNATION",
        [0x4000002C] = "FIRMWARE UPDATED",
        [0x4000002D] = "DRIVERS LEAKING LOCKED PAGES",
        [0x4000002E] = "MESSAGE RETRIEVED",
        [0x4000002F] = "SYSTEM POWERSTATE TRANSITION",
        [0x40000030] = "ALPC CHECK COMPLETION LIST",
        [0x40000031] = "SYSTEM POWERSTATE COMPLEX TRANSITION",
        [0x40000032] = "ACCESS AUDIT BY POLICY",
        [0x40000033] = "ABANDON HIBERFILE",
        [0x40000034] = "BIZRULES NOT ENABLED",
        [0x40000294] = "WAKE SYSTEM",
        [0x40000370] = "DS SHUTTING DOWN",
        [0x40010001] = "DBG REPLY LATER",
        [0x40010002] = "DBG UNABLE TO PROVIDE HANDLE",
        [0x40010003] = "DBG TERMINATE THREAD",
        [0x40010004] = "DBG TERMINATE PROCESS",
        [0x40010005] = "DBG CONTROL C",
        [0x40010006] = "DBG PRINTEXCEPTION C",
        [0x40010007] = "DBG RIPEXCEPTION",
        [0x40010008] = "DBG CONTROL BREAK",
        [0x40010009] = "DBG COMMAND EXCEPTION",
        [0x40020056] = "RPC NT UUID LOCAL ONLY",
        [0x400200AF] = "RPC NT SEND INCOMPLETE",
        [0x400A0004] = "CTX CDM CONNECT",
        [0x400A0005] = "CTX CDM DISCONNECT",
        [0x4015000D] = "SXS RELEASE ACTIVATION CONTEXT",
        [0x40190034] = "RECOVERY NOT NEEDED",
        [0x40190035] = "RM ALREADY STARTED",
        [0x401A000C] = "LOG NO RESTART",
        [0x401E000A] = "GRAPHICS PARTIAL DATA POPULATED",
        [0x401E0117] = "GRAPHICS DRIVER MISMATCH",
        [0x401E0307] = "GRAPHICS MODE NOT PINNED",
        [0x401E031E] = "GRAPHICS NO PREFERRED MODE",
        [0x401E034B] = "GRAPHICS DATASET IS EMPTY",
        [0x401E034C] = "GRAPHICS NO MORE ELEMENTS IN DATASET",
        [0x401E0351] = "GRAPHICS PATH CONTENT GEOMETRY TRANSFORMATION NOT PINNED",
        [0x401E042F] = "GRAPHICS UNKNOWN CHILD STATUS",
        [0x401E0437] = "GRAPHICS LEADLINK START DEFERRED",
        [0x401E0439] = "GRAPHICS POLLING TOO FREQUENTLY",
        [0x401E043A] = "GRAPHICS START DEFERRED",
        [0x40230001] = "NDIS INDICATION REQUIRED",
        [0x80000001] = "GUARD PAGE VIOLATION",
        [0x80000002] = "DATATYPE MISALIGNMENT",
        [0x80000003] = "BREAKPOINT",
        [0x80000004] = "SINGLE STEP",
        [0x80000005] = "BUFFER OVERFLOW",
        [0x80000006] = "NO MORE FILES",
        [0x8000000A] = "HANDLES CLOSED",
        [0x8000000B] = "NO INHERITANCE",
        [0x8000000C] = "GUID SUBSTITUTION MADE",
        [0x8000000D] = "PARTIAL COPY",
        [0x8000000E] = "DEVICE PAPER EMPTY",
        [0x8000000F] = "DEVICE POWERED OFF",
        [0x80000010] = "DEVICE OFF LINE",
        [0x80000011] = "DEVICE BUSY",
        [0x80000012] = "NO MORE EAS",
        [0x80000013] = "INVALID EA NAME",
        [0x80000014] = "EA LIST INCONSISTENT",
        [0x80000015] = "INVALID EA FLAG",
        [0x80000016] = "VERIFY REQUIRED",
        [0x80000017] = "EXTRANEOUS INFORMATION",
        [0x80000018] = "RXACT COMMIT NECESSARY",
        [0x8000001A] = "NO MORE ENTRIES",
        [0x8000001B] = "FILEMARK DETECTED",
        [0x8000001C] = "MEDIA CHANGED",
        [0x8000001D] = "BUS RESET",
        [0x8000001E] = "END OF MEDIA",
        [0x8000001F] = "BEGINNING OF MEDIA",
        [0x80000020] = "MEDIA CHECK",
        [0x80000021] = "SETMARK DETECTED",
        [0x80000022] = "NO DATA DETECTED",
        [0x80000023] = "REDIRECTOR HAS OPEN HANDLES",
        [0x80000024] = "SERVER HAS OPEN HANDLES",
        [0x80000025] = "ALREADY DISCONNECTED",
        [0x80000026] = "LONGJUMP",
        [0x80000027] = "CLEANER CARTRIDGE INSTALLED",
        [0x80000028] = "PLUGPLAY QUERY VETOED",
        [0x80000029] = "UNWIND CONSOLIDATE",
        [0x8000002A] = "REGISTRY HIVE RECOVERED",
        [0x8000002B] = "DLL MIGHT BE INSECURE",
        [0x8000002C] = "DLL MIGHT BE INCOMPATIBLE",
        [0x8000002D] = "STOPPED ON SYMLINK",
        [0x80000288] = "DEVICE REQUIRES CLEANING",
        [0x80000289] = "DEVICE DOOR OPEN",
        [0x80000803] = "DATA LOST REPAIR",
        [0x80010001] = "DBG EXCEPTION NOT HANDLED",
        [0x80130001] = "CLUSTER NODE ALREADY UP",
        [0x80130002] = "CLUSTER NODE ALREADY DOWN",
        [0x80130003] = "CLUSTER NETWORK ALREADY ONLINE",
        [0x80130004] = "CLUSTER NETWORK ALREADY OFFLINE",
        [0x80130005] = "CLUSTER NODE ALREADY MEMBER",
        [0x80190009] = "COULD NOT RESIZE LOG",
        [0x80190029] = "NO TXF METADATA",
        [0x80190031] = "CANT RECOVER WITH HANDLE OPEN",
        [0x80190041] = "TXF METADATA ALREADY PRESENT",
        [0x80190042] = "TRANSACTION SCOPE CALLBACKS NOT SET",
        [0x801B00EB] = "VIDEO HUNG DISPLAY DRIVER THREAD RECOVERED",
        [0x801C0001] = "FLT BUFFER TOO SMALL",
        [0x80210001] = "FVE PARTIAL METADATA",
        [0x80210002] = "FVE TRANSIENT STATE",
        [0xC0000001] = "UNSUCCESSFUL",
        [0xC0000002] = "NOT IMPLEMENTED",
        [0xC0000003] = "INVALID INFO CLASS",
        [0xC0000004] = "INFO LENGTH MISMATCH",
        [0xC0000005] = "ACCESS VIOLATION",
        [0xC0000006] = "IN PAGE ERROR",
        [0xC0000007] = "PAGEFILE QUOTA",
        [0xC0000008] = "INVALID HANDLE",
        [0xC0000009] = "BAD INITIAL STACK",
        [0xC000000A] = "BAD INITIAL PC",
        [0xC000000B] = "INVALID CID",
        [0xC000000C] = "TIMER NOT CANCELED",
        [0xC000000D] = "INVALID PARAMETER",
        [0xC000000E] = "NO SUCH DEVICE",
        [0xC000000F] = "NO SUCH FILE",
        [0xC0000010] = "INVALID DEVICE REQUEST",
        [0xC0000011] = "END OF FILE",
        [0xC0000012] = "WRONG VOLUME",
        [0xC0000013] = "NO MEDIA IN DEVICE",
        [0xC0000014] = "UNRECOGNIZED MEDIA",
        [0xC0000015] = "NONEXISTENT SECTOR",
        [0xC0000016] = "MORE PROCESSING REQUIRED",
        [0xC0000017] = "NO MEMORY",
        [0xC0000018] = "CONFLICTING ADDRESSES",
        [0xC0000019] = "NOT MAPPED VIEW",
        [0xC000001A] = "UNABLE TO FREE VM",
        [0xC000001B] = "UNABLE TO DELETE SECTION",
        [0xC000001C] = "INVALID SYSTEM SERVICE",
        [0xC000001D] = "ILLEGAL INSTRUCTION",
        [0xC000001E] = "INVALID LOCK SEQUENCE",
        [0xC000001F] = "INVALID VIEW SIZE",
        [0xC0000020] = "INVALID FILE FOR SECTION",
        [0xC0000021] = "ALREADY COMMITTED",
        [0xC0000022] = "ACCESS DENIED",
        [0xC0000023] = "BUFFER TOO SMALL",
        [0xC0000024] = "OBJECT TYPE MISMATCH",
        [0xC0000025] = "NONCONTINUABLE EXCEPTION",
        [0xC0000026] = "INVALID DISPOSITION",
        [0xC0000027] = "UNWIND",
        [0xC0000028] = "BAD STACK",
        [0xC0000029] = "INVALID UNWIND TARGET",
        [0xC000002A] = "NOT LOCKED",
        [0xC000002B] = "PARITY ERROR",
        [0xC000002C] = "UNABLE TO DECOMMIT VM",
        [0xC000002D] = "NOT COMMITTED",
        [0xC000002E] = "INVALID PORT ATTRIBUTES",
        [0xC000002F] = "PORT MESSAGE TOO LONG",
        [0xC0000030] = "INVALID PARAMETER MIX",
        [0xC0000031] = "INVALID QUOTA LOWER",
        [0xC0000032] = "DISK CORRUPT ERROR",
        [0xC0000033] = "OBJECT NAME INVALID",
        [0xC0000034] = "OBJECT NAME NOT FOUND",
        [0xC0000035] = "OBJECT NAME COLLISION",
        [0xC0000037] = "PORT DISCONNECTED",
        [0xC0000038] = "DEVICE ALREADY ATTACHED",
        [0xC0000039] = "OBJECT PATH INVALID",
        [0xC000003A] = "OBJECT PATH NOT FOUND",
        [0xC000003B] = "OBJECT PATH SYNTAX BAD",
        [0xC000003C] = "DATA OVERRUN",
        [0xC000003D] = "DATA LATE ERROR",
        [0xC000003E] = "DATA ERROR",
        [0xC000003F] = "CRC ERROR",
        [0xC0000040] = "SECTION TOO BIG",
        [0xC0000041] = "PORT CONNECTION REFUSED",
        [0xC0000042] = "INVALID PORT HANDLE",
        [0xC0000043] = "SHARING VIOLATION",
        [0xC0000044] = "QUOTA EXCEEDED",
        [0xC0000045] = "INVALID PAGE PROTECTION",
        [0xC0000046] = "MUTANT NOT OWNED",
        [0xC0000047] = "SEMAPHORE LIMIT EXCEEDED",
        [0xC0000048] = "PORT ALREADY SET",
        [0xC0000049] = "SECTION NOT IMAGE",
        [0xC000004A] = "SUSPEND COUNT EXCEEDED",
        [0xC000004B] = "THREAD IS TERMINATING",
        [0xC000004C] = "BAD WORKING SET LIMIT",
        [0xC000004D] = "INCOMPATIBLE FILE MAP",
        [0xC000004E] = "SECTION PROTECTION",
        [0xC000004F] = "EAS NOT SUPPORTED",
        [0xC0000050] = "EA TOO LARGE",
        [0xC0000051] = "NONEXISTENT EA ENTRY",
        [0xC0000052] = "NO EAS ON FILE",
        [0xC0000053] = "EA CORRUPT ERROR",
        [0xC0000054] = "FILE LOCK CONFLICT",
        [0xC0000055] = "LOCK NOT GRANTED",
        [0xC0000056] = "DELETE PENDING",
        [0xC0000057] = "CTL FILE NOT SUPPORTED",
        [0xC0000058] = "UNKNOWN REVISION",
        [0xC0000059] = "REVISION MISMATCH",
        [0xC000005A] = "INVALID OWNER",
        [0xC000005B] = "INVALID PRIMARY GROUP",
        [0xC000005C] = "NO IMPERSONATION TOKEN",
        [0xC000005D] = "CANT DISABLE MANDATORY",
        [0xC000005E] = "NO LOGON SERVERS",
        [0xC000005F] = "NO SUCH LOGON SESSION",
        [0xC0000060] = "NO SUCH PRIVILEGE",
        [0xC0000061] = "PRIVILEGE NOT HELD",
        [0xC0000062] = "INVALID ACCOUNT NAME",
        [0xC0000063] = "USER EXISTS",
        [0xC0000064] = "NO SUCH USER",
        [0xC0000065] = "GROUP EXISTS",
        [0xC0000066] = "NO SUCH GROUP",
        [0xC0000067] = "MEMBER IN GROUP",
        [0xC0000068] = "MEMBER NOT IN GROUP",
        [0xC0000069] = "LAST ADMIN",
        [0xC000006A] = "WRONG PASSWORD",
        [0xC000006B] = "ILL FORMED PASSWORD",
        [0xC000006C] = "PASSWORD RESTRICTION",
        [0xC000006D] = "LOGON FAILURE",
        [0xC000006E] = "ACCOUNT RESTRICTION",
        [0xC000006F] = "INVALID LOGON HOURS",
        [0xC0000070] = "INVALID WORKSTATION",
        [0xC0000071] = "PASSWORD EXPIRED",
        [0xC0000072] = "ACCOUNT DISABLED",
        [0xC0000073] = "NONE MAPPED",
        [0xC0000074] = "TOO MANY LUIDS REQUESTED",
        [0xC0000075] = "LUIDS EXHAUSTED",
        [0xC0000076] = "INVALID SUB AUTHORITY",
        [0xC0000077] = "INVALID ACL",
        [0xC0000078] = "INVALID SID",
        [0xC0000079] = "INVALID SECURITY DESCR",
        [0xC000007A] = "PROCEDURE NOT FOUND",
        [0xC000007B] = "INVALID IMAGE FORMAT",
        [0xC000007C] = "NO TOKEN",
        [0xC000007D] = "BAD INHERITANCE ACL",
        [0xC000007E] = "RANGE NOT LOCKED",
        [0xC000007F] = "DISK FULL",
        [0xC0000080] = "SERVER DISABLED",
        [0xC0000081] = "SERVER NOT DISABLED",
        [0xC0000082] = "TOO MANY GUIDS REQUESTED",
        [0xC0000083] = "GUIDS EXHAUSTED",
        [0xC0000084] = "INVALID ID AUTHORITY",
        [0xC0000085] = "AGENTS EXHAUSTED",
        [0xC0000086] = "INVALID VOLUME LABEL",
        [0xC0000087] = "SECTION NOT EXTENDED",
        [0xC0000088] = "NOT MAPPED DATA",
        [0xC0000089] = "RESOURCE DATA NOT FOUND",
        [0xC000008A] = "RESOURCE TYPE NOT FOUND",
        [0xC000008B] = "RESOURCE NAME NOT FOUND",
        [0xC000008C] = "ARRAY BOUNDS EXCEEDED",
        [0xC000008D] = "FLOAT DENORMAL OPERAND",
        [0xC000008E] = "FLOAT DIVIDE BY ZERO",
        [0xC000008F] = "FLOAT INEXACT RESULT",
        [0xC0000090] = "FLOAT INVALID OPERATION",
        [0xC0000091] = "FLOAT OVERFLOW",
        [0xC0000092] = "FLOAT STACK CHECK",
        [0xC0000093] = "FLOAT UNDERFLOW",
        [0xC0000094] = "INTEGER DIVIDE BY ZERO",
        [0xC0000095] = "INTEGER OVERFLOW",
        [0xC0000096] = "PRIVILEGED INSTRUCTION",
        [0xC0000097] = "TOO MANY PAGING FILES",
        [0xC0000098] = "FILE INVALID",
        [0xC0000099] = "ALLOTTED SPACE EXCEEDED",
        [0xC000009A] = "INSUFFICIENT RESOURCES",
        [0xC000009B] = "DFS EXIT PATH FOUND",
        [0xC000009C] = "DEVICE DATA ERROR",
        [0xC000009D] = "DEVICE NOT CONNECTED",
        [0xC000009F] = "FREE VM NOT AT BASE",
        [0xC00000A0] = "MEMORY NOT ALLOCATED",
        [0xC00000A1] = "WORKING SET QUOTA",
        [0xC00000A2] = "MEDIA WRITE PROTECTED",
        [0xC00000A3] = "DEVICE NOT READY",
        [0xC00000A4] = "INVALID GROUP ATTRIBUTES",
        [0xC00000A5] = "BAD IMPERSONATION LEVEL",
        [0xC00000A6] = "CANT OPEN ANONYMOUS",
        [0xC00000A7] = "BAD VALIDATION CLASS",
        [0xC00000A8] = "BAD TOKEN TYPE",
        [0xC00000A9] = "BAD MASTER BOOT RECORD",
        [0xC00000AA] = "INSTRUCTION MISALIGNMENT",
        [0xC00000AB] = "INSTANCE NOT AVAILABLE",
        [0xC00000AC] = "PIPE NOT AVAILABLE",
        [0xC00000AD] = "INVALID PIPE STATE",
        [0xC00000AE] = "PIPE BUSY",
        [0xC00000AF] = "ILLEGAL FUNCTION",
        [0xC00000B0] = "PIPE DISCONNECTED",
        [0xC00000B1] = "PIPE CLOSING",
        [0xC00000B2] = "PIPE CONNECTED",
        [0xC00000B3] = "PIPE LISTENING",
        [0xC00000B4] = "INVALID READ MODE",
        [0xC00000B5] = "IO TIMEOUT",
        [0xC00000B6] = "FILE FORCED CLOSED",
        [0xC00000B7] = "PROFILING NOT STARTED",
        [0xC00000B8] = "PROFILING NOT STOPPED",
        [0xC00000B9] = "COULD NOT INTERPRET",
        [0xC00000BA] = "FILE IS A DIRECTORY",
        [0xC00000BB] = "NOT SUPPORTED",
        [0xC00000BC] = "REMOTE NOT LISTENING",
        [0xC00000BD] = "DUPLICATE NAME",
        [0xC00000BE] = "BAD NETWORK PATH",
        [0xC00000BF] = "NETWORK BUSY",
        [0xC00000C0] = "DEVICE DOES NOT EXIST",
        [0xC00000C1] = "TOO MANY COMMANDS",
        [0xC00000C2] = "ADAPTER HARDWARE ERROR",
        [0xC00000C3] = "INVALID NETWORK RESPONSE",
        [0xC00000C4] = "UNEXPECTED NETWORK ERROR",
        [0xC00000C5] = "BAD REMOTE ADAPTER",
        [0xC00000C6] = "PRINT QUEUE FULL",
        [0xC00000C7] = "NO SPOOL SPACE",
        [0xC00000C8] = "PRINT CANCELLED",
        [0xC00000C9] = "NETWORK NAME DELETED",
        [0xC00000CA] = "NETWORK ACCESS DENIED",
        [0xC00000CB] = "BAD DEVICE TYPE",
        [0xC00000CC] = "BAD NETWORK NAME",
        [0xC00000CD] = "TOO MANY NAMES",
        [0xC00000CE] = "TOO MANY SESSIONS",
        [0xC00000CF] = "SHARING PAUSED",
        [0xC00000D0] = "REQUEST NOT ACCEPTED",
        [0xC00000D1] = "REDIRECTOR PAUSED",
        [0xC00000D2] = "NET WRITE FAULT",
        [0xC00000D3] = "PROFILING AT LIMIT",
        [0xC00000D4] = "NOT SAME DEVICE",
        [0xC00000D5] = "FILE RENAMED",
        [0xC00000D6] = "VIRTUAL CIRCUIT CLOSED",
        [0xC00000D7] = "NO SECURITY ON OBJECT",
        [0xC00000D8] = "CANT WAIT",
        [0xC00000D9] = "PIPE EMPTY",
        [0xC00000DA] = "CANT ACCESS DOMAIN INFO",
        [0xC00000DB] = "CANT TERMINATE SELF",
        [0xC00000DC] = "INVALID SERVER STATE",
        [0xC00000DD] = "INVALID DOMAIN STATE",
        [0xC00000DE] = "INVALID DOMAIN ROLE",
        [0xC00000DF] = "NO SUCH DOMAIN",
        [0xC00000E0] = "DOMAIN EXISTS",
        [0xC00000E1] = "DOMAIN LIMIT EXCEEDED",
        [0xC00000E2] = "OPLOCK NOT GRANTED",
        [0xC00000E3] = "INVALID OPLOCK PROTOCOL",
        [0xC00000E4] = "INTERNAL DB CORRUPTION",
        [0xC00000E5] = "INTERNAL ERROR",
        [0xC00000E6] = "GENERIC NOT MAPPED",
        [0xC00000E7] = "BAD DESCRIPTOR FORMAT",
        [0xC00000E8] = "INVALID USER BUFFER",
        [0xC00000E9] = "UNEXPECTED IO ERROR",
        [0xC00000EA] = "UNEXPECTED MM CREATE ERR",
        [0xC00000EB] = "UNEXPECTED MM MAP ERROR",
        [0xC00000EC] = "UNEXPECTED MM EXTEND ERR",
        [0xC00000ED] = "NOT LOGON PROCESS",
        [0xC00000EE] = "LOGON SESSION EXISTS",
        [0xC00000EF] = "INVALID PARAMETER 1",
        [0xC00000F0] = "INVALID PARAMETER 2",
        [0xC00000F1] = "INVALID PARAMETER 3",
        [0xC00000F2] = "INVALID PARAMETER 4",
        [0xC00000F3] = "INVALID PARAMETER 5",
        [0xC00000F4] = "INVALID PARAMETER 6",
        [0xC00000F5] = "INVALID PARAMETER 7",
        [0xC00000F6] = "INVALID PARAMETER 8",
        [0xC00000F7] = "INVALID PARAMETER 9",
        [0xC00000F8] = "INVALID PARAMETER 10",
        [0xC00000F9] = "INVALID PARAMETER 11",
        [0xC00000FA] = "INVALID PARAMETER 12",
        [0xC00000FB] = "REDIRECTOR NOT STARTED",
        [0xC00000FC] = "REDIRECTOR STARTED",
        [0xC00000FD] = "STACK OVERFLOW",
        [0xC00000FE] = "NO SUCH PACKAGE",
        [0xC00000FF] = "BAD FUNCTION TABLE",
        [0xC0000100] = "VARIABLE NOT FOUND",
        [0xC0000101] = "DIRECTORY NOT EMPTY",
        [0xC0000102] = "FILE CORRUPT ERROR",
        [0xC0000103] = "NOT A DIRECTORY",
        [0xC0000104] = "BAD LOGON SESSION STATE",
        [0xC0000105] = "LOGON SESSION COLLISION",
        [0xC0000106] = "NAME TOO LONG",
        [0xC0000107] = "FILES OPEN",
        [0xC0000108] = "CONNECTION IN USE",
        [0xC0000109] = "MESSAGE NOT FOUND",
        [0xC000010A] = "PROCESS IS TERMINATING",
        [0xC000010B] = "INVALID LOGON TYPE",
        [0xC000010C] = "NO GUID TRANSLATION",
        [0xC000010D] = "CANNOT IMPERSONATE",
        [0xC000010E] = "IMAGE ALREADY LOADED",
        [0xC0000117] = "NO LDT",
        [0xC0000118] = "INVALID LDT SIZE",
        [0xC0000119] = "INVALID LDT OFFSET",
        [0xC000011A] = "INVALID LDT DESCRIPTOR",
        [0xC000011B] = "INVALID IMAGE NE FORMAT",
        [0xC000011C] = "RXACT INVALID STATE",
        [0xC000011D] = "RXACT COMMIT FAILURE",
        [0xC000011E] = "MAPPED FILE SIZE ZERO",
        [0xC000011F] = "TOO MANY OPENED FILES",
        [0xC0000120] = "CANCELLED",
        [0xC0000121] = "CANNOT DELETE",
        [0xC0000122] = "INVALID COMPUTER NAME",
        [0xC0000123] = "FILE DELETED",
        [0xC0000124] = "SPECIAL ACCOUNT",
        [0xC0000125] = "SPECIAL GROUP",
        [0xC0000126] = "SPECIAL USER",
        [0xC0000127] = "MEMBERS PRIMARY GROUP",
        [0xC0000128] = "FILE CLOSED",
        [0xC0000129] = "TOO MANY THREADS",
        [0xC000012A] = "THREAD NOT IN PROCESS",
        [0xC000012B] = "TOKEN ALREADY IN USE",
        [0xC000012C] = "PAGEFILE QUOTA EXCEEDED",
        [0xC000012D] = "COMMITMENT LIMIT",
        [0xC000012E] = "INVALID IMAGE LE FORMAT",
        [0xC000012F] = "INVALID IMAGE NOT MZ",
        [0xC0000130] = "INVALID IMAGE PROTECT",
        [0xC0000131] = "INVALID IMAGE WIN 16",
        [0xC0000132] = "LOGON SERVER CONFLICT",
        [0xC0000133] = "TIME DIFFERENCE AT DC",
        [0xC0000134] = "SYNCHRONIZATION REQUIRED",
        [0xC0000135] = "DLL NOT FOUND",
        [0xC0000136] = "OPEN FAILED",
        [0xC0000137] = "IO PRIVILEGE FAILED",
        [0xC0000138] = "ORDINAL NOT FOUND",
        [0xC0000139] = "ENTRYPOINT NOT FOUND",
        [0xC000013A] = "CONTROL C EXIT",
        [0xC000013B] = "LOCAL DISCONNECT",
        [0xC000013C] = "REMOTE DISCONNECT",
        [0xC000013D] = "REMOTE RESOURCES",
        [0xC000013E] = "LINK FAILED",
        [0xC000013F] = "LINK TIMEOUT",
        [0xC0000140] = "INVALID CONNECTION",
        [0xC0000141] = "INVALID ADDRESS",
        [0xC0000142] = "DLL INIT FAILED",
        [0xC0000143] = "MISSING SYSTEMFILE",
        [0xC0000144] = "UNHANDLED EXCEPTION",
        [0xC0000145] = "APP INIT FAILURE",
        [0xC0000146] = "PAGEFILE CREATE FAILED",
        [0xC0000147] = "NO PAGEFILE",
        [0xC0000148] = "INVALID LEVEL",
        [0xC0000149] = "WRONG PASSWORD CORE",
        [0xC000014A] = "ILLEGAL FLOAT CONTEXT",
        [0xC000014B] = "PIPE BROKEN",
        [0xC000014C] = "REGISTRY CORRUPT",
        [0xC000014D] = "REGISTRY IO FAILED",
        [0xC000014E] = "NO EVENT PAIR",
        [0xC000014F] = "UNRECOGNIZED VOLUME",
        [0xC0000150] = "SERIAL NO DEVICE INITED",
        [0xC0000151] = "NO SUCH ALIAS",
        [0xC0000152] = "MEMBER NOT IN ALIAS",
        [0xC0000153] = "MEMBER IN ALIAS",
        [0xC0000154] = "ALIAS EXISTS",
        [0xC0000155] = "LOGON NOT GRANTED",
        [0xC0000156] = "TOO MANY SECRETS",
        [0xC0000157] = "SECRET TOO LONG",
        [0xC0000158] = "INTERNAL DB ERROR",
        [0xC0000159] = "FULLSCREEN MODE",
        [0xC000015A] = "TOO MANY CONTEXT IDS",
        [0xC000015B] = "LOGON TYPE NOT GRANTED",
        [0xC000015C] = "NOT REGISTRY FILE",
        [0xC000015D] = "NT CROSS ENCRYPTION REQUIRED",
        [0xC000015E] = "DOMAIN CTRLR CONFIG ERROR",
        [0xC000015F] = "FT MISSING MEMBER",
        [0xC0000160] = "ILL FORMED SERVICE ENTRY",
        [0xC0000161] = "ILLEGAL CHARACTER",
        [0xC0000162] = "UNMAPPABLE CHARACTER",
        [0xC0000163] = "UNDEFINED CHARACTER",
        [0xC0000164] = "FLOPPY VOLUME",
        [0xC0000165] = "FLOPPY ID MARK NOT FOUND",
        [0xC0000166] = "FLOPPY WRONG CYLINDER",
        [0xC0000167] = "FLOPPY UNKNOWN ERROR",
        [0xC0000168] = "FLOPPY BAD REGISTERS",
        [0xC0000169] = "DISK RECALIBRATE FAILED",
        [0xC000016A] = "DISK OPERATION FAILED",
        [0xC000016B] = "DISK RESET FAILED",
        [0xC000016C] = "SHARED IRQ BUSY",
        [0xC000016D] = "FT ORPHANING",
        [0xC000016E] = "BIOS FAILED TO CONNECT INTERRUPT",
        [0xC0000172] = "PARTITION FAILURE",
        [0xC0000173] = "INVALID BLOCK LENGTH",
        [0xC0000174] = "DEVICE NOT PARTITIONED",
        [0xC0000175] = "UNABLE TO LOCK MEDIA",
        [0xC0000176] = "UNABLE TO UNLOAD MEDIA",
        [0xC0000177] = "EOM OVERFLOW",
        [0xC0000178] = "NO MEDIA",
        [0xC000017A] = "NO SUCH MEMBER",
        [0xC000017B] = "INVALID MEMBER",
        [0xC000017C] = "KEY DELETED",
        [0xC000017D] = "NO LOG SPACE",
        [0xC000017E] = "TOO MANY SIDS",
        [0xC000017F] = "LM CROSS ENCRYPTION REQUIRED",
        [0xC0000180] = "KEY HAS CHILDREN",
        [0xC0000181] = "CHILD MUST BE VOLATILE",
        [0xC0000182] = "DEVICE CONFIGURATION ERROR",
        [0xC0000183] = "DRIVER INTERNAL ERROR",
        [0xC0000184] = "INVALID DEVICE STATE",
        [0xC0000185] = "IO DEVICE ERROR",
        [0xC0000186] = "DEVICE PROTOCOL ERROR",
        [0xC0000187] = "BACKUP CONTROLLER",
        [0xC0000188] = "LOG FILE FULL",
        [0xC0000189] = "TOO LATE",
        [0xC000018A] = "NO TRUST LSA SECRET",
        [0xC000018B] = "NO TRUST SAM ACCOUNT",
        [0xC000018C] = "TRUSTED DOMAIN FAILURE",
        [0xC000018D] = "TRUSTED RELATIONSHIP FAILURE",
        [0xC000018E] = "EVENTLOG FILE CORRUPT",
        [0xC000018F] = "EVENTLOG CANT START",
        [0xC0000190] = "TRUST FAILURE",
        [0xC0000191] = "MUTANT LIMIT EXCEEDED",
        [0xC0000192] = "NETLOGON NOT STARTED",
        [0xC0000193] = "ACCOUNT EXPIRED",
        [0xC0000194] = "POSSIBLE DEADLOCK",
        [0xC0000195] = "NETWORK CREDENTIAL CONFLICT",
        [0xC0000196] = "REMOTE SESSION LIMIT",
        [0xC0000197] = "EVENTLOG FILE CHANGED",
        [0xC0000198] = "NOLOGON INTERDOMAIN TRUST ACCOUNT",
        [0xC0000199] = "NOLOGON WORKSTATION TRUST ACCOUNT",
        [0xC000019A] = "NOLOGON SERVER TRUST ACCOUNT",
        [0xC000019B] = "DOMAIN TRUST INCONSISTENT",
        [0xC000019C] = "FS DRIVER REQUIRED",
        [0xC000019D] = "IMAGE ALREADY LOADED AS DLL",
        [0xC000019E] = "INCOMPATIBLE WITH GLOBAL SHORT NAME REGISTRY SETTING",
        [0xC000019F] = "SHORT NAMES NOT ENABLED ON VOLUME",
        [0xC00001A0] = "SECURITY STREAM IS INCONSISTENT",
        [0xC00001A1] = "INVALID LOCK RANGE",
        [0xC00001A2] = "INVALID ACE CONDITION",
        [0xC00001A3] = "IMAGE SUBSYSTEM NOT PRESENT",
        [0xC00001A4] = "NOTIFICATION GUID ALREADY DEFINED",
        [0xC0000201] = "NETWORK OPEN RESTRICTION",
        [0xC0000202] = "NO USER SESSION KEY",
        [0xC0000203] = "USER SESSION DELETED",
        [0xC0000204] = "RESOURCE LANG NOT FOUND",
        [0xC0000205] = "INSUFF SERVER RESOURCES",
        [0xC0000206] = "INVALID BUFFER SIZE",
        [0xC0000207] = "INVALID ADDRESS COMPONENT",
        [0xC0000208] = "INVALID ADDRESS WILDCARD",
        [0xC0000209] = "TOO MANY ADDRESSES",
        [0xC000020A] = "ADDRESS ALREADY EXISTS",
        [0xC000020B] = "ADDRESS CLOSED",
        [0xC000020C] = "CONNECTION DISCONNECTED",
        [0xC000020D] = "CONNECTION RESET",
        [0xC000020E] = "TOO MANY NODES",
        [0xC000020F] = "TRANSACTION ABORTED",
        [0xC0000210] = "TRANSACTION TIMED OUT",
        [0xC0000211] = "TRANSACTION NO RELEASE",
        [0xC0000212] = "TRANSACTION NO MATCH",
        [0xC0000213] = "TRANSACTION RESPONDED",
        [0xC0000214] = "TRANSACTION INVALID ID",
        [0xC0000215] = "TRANSACTION INVALID TYPE",
        [0xC0000216] = "NOT SERVER SESSION",
        [0xC0000217] = "NOT CLIENT SESSION",
        [0xC0000218] = "CANNOT LOAD REGISTRY FILE",
        [0xC000021A] = "SYSTEM PROCESS TERMINATED",
        [0xC000021B] = "DATA NOT ACCEPTED",
        [0xC000021C] = "NO BROWSER SERVERS FOUND",
        [0xC000021D] = "VDM HARD ERROR",
        [0xC000021E] = "DRIVER CANCEL TIMEOUT",
        [0xC000021F] = "REPLY MESSAGE MISMATCH",
        [0xC0000220] = "MAPPED ALIGNMENT",
        [0xC0000221] = "IMAGE CHECKSUM MISMATCH",
        [0xC0000222] = "LOST WRITEBEHIND DATA",
        [0xC0000223] = "CLIENT SERVER PARAMETERS INVALID",
        [0xC0000224] = "PASSWORD MUST CHANGE",
        [0xC0000225] = "NOT FOUND",
        [0xC0000226] = "NOT TINY STREAM",
        [0xC0000227] = "RECOVERY FAILURE",
        [0xC0000228] = "STACK OVERFLOW READ",
        [0xC0000229] = "FAIL CHECK",
        [0xC000022A] = "DUPLICATE OBJECTID",
        [0xC000022B] = "OBJECTID EXISTS",
        [0xC000022C] = "CONVERT TO LARGE",
        [0xC000022D] = "RETRY",
        [0xC000022E] = "FOUND OUT OF SCOPE",
        [0xC000022F] = "ALLOCATE BUCKET",
        [0xC0000230] = "PROPSET NOT FOUND",
        [0xC0000231] = "MARSHALL OVERFLOW",
        [0xC0000232] = "INVALID VARIANT",
        [0xC0000233] = "DOMAIN CONTROLLER NOT FOUND",
        [0xC0000234] = "ACCOUNT LOCKED OUT",
        [0xC0000235] = "HANDLE NOT CLOSABLE",
        [0xC0000236] = "CONNECTION REFUSED",
        [0xC0000237] = "GRACEFUL DISCONNECT",
        [0xC0000238] = "ADDRESS ALREADY ASSOCIATED",
        [0xC0000239] = "ADDRESS NOT ASSOCIATED",
        [0xC000023A] = "CONNECTION INVALID",
        [0xC000023B] = "CONNECTION ACTIVE",
        [0xC000023C] = "NETWORK UNREACHABLE",
        [0xC000023D] = "HOST UNREACHABLE",
        [0xC000023E] = "PROTOCOL UNREACHABLE",
        [0xC000023F] = "PORT UNREACHABLE",
        [0xC0000240] = "REQUEST ABORTED",
        [0xC0000241] = "CONNECTION ABORTED",
        [0xC0000242] = "BAD COMPRESSION BUFFER",
        [0xC0000243] = "USER MAPPED FILE",
        [0xC0000244] = "AUDIT FAILED",
        [0xC0000245] = "TIMER RESOLUTION NOT SET",
        [0xC0000246] = "CONNECTION COUNT LIMIT",
        [0xC0000247] = "LOGIN TIME RESTRICTION",
        [0xC0000248] = "LOGIN WKSTA RESTRICTION",
        [0xC0000249] = "IMAGE MP UP MISMATCH",
        [0xC0000250] = "INSUFFICIENT LOGON INFO",
        [0xC0000251] = "BAD DLL ENTRYPOINT",
        [0xC0000252] = "BAD SERVICE ENTRYPOINT",
        [0xC0000253] = "LPC REPLY LOST",
        [0xC0000254] = "IP ADDRESS CONFLICT1",
        [0xC0000255] = "IP ADDRESS CONFLICT2",
        [0xC0000256] = "REGISTRY QUOTA LIMIT",
        [0xC0000257] = "PATH NOT COVERED",
        [0xC0000258] = "NO CALLBACK ACTIVE",
        [0xC0000259] = "LICENSE QUOTA EXCEEDED",
        [0xC000025A] = "PWD TOO SHORT",
        [0xC000025B] = "PWD TOO RECENT",
        [0xC000025C] = "PWD HISTORY CONFLICT",
        [0xC000025E] = "PLUGPLAY NO DEVICE",
        [0xC000025F] = "UNSUPPORTED COMPRESSION",
        [0xC0000260] = "INVALID HW PROFILE",
        [0xC0000261] = "INVALID PLUGPLAY DEVICE PATH",
        [0xC0000262] = "DRIVER ORDINAL NOT FOUND",
        [0xC0000263] = "DRIVER ENTRYPOINT NOT FOUND",
        [0xC0000264] = "RESOURCE NOT OWNED",
        [0xC0000265] = "TOO MANY LINKS",
        [0xC0000266] = "QUOTA LIST INCONSISTENT",
        [0xC0000267] = "FILE IS OFFLINE",
        [0xC0000268] = "EVALUATION EXPIRATION",
        [0xC0000269] = "ILLEGAL DLL RELOCATION",
        [0xC000026A] = "LICENSE VIOLATION",
        [0xC000026B] = "DLL INIT FAILED LOGOFF",
        [0xC000026C] = "DRIVER UNABLE TO LOAD",
        [0xC000026D] = "DFS UNAVAILABLE",
        [0xC000026E] = "VOLUME DISMOUNTED",
        [0xC000026F] = "WX86 INTERNAL ERROR",
        [0xC0000270] = "WX86 FLOAT STACK CHECK",
        [0xC0000271] = "VALIDATE CONTINUE",
        [0xC0000272] = "NO MATCH",
        [0xC0000273] = "NO MORE MATCHES",
        [0xC0000275] = "NOT A REPARSE POINT",
        [0xC0000276] = "IO REPARSE TAG INVALID",
        [0xC0000277] = "IO REPARSE TAG MISMATCH",
        [0xC0000278] = "IO REPARSE DATA INVALID",
        [0xC0000279] = "IO REPARSE TAG NOT HANDLED",
        [0xC0000280] = "REPARSE POINT NOT RESOLVED",
        [0xC0000281] = "DIRECTORY IS A REPARSE POINT",
        [0xC0000282] = "RANGE LIST CONFLICT",
        [0xC0000283] = "SOURCE ELEMENT EMPTY",
        [0xC0000284] = "DESTINATION ELEMENT FULL",
        [0xC0000285] = "ILLEGAL ELEMENT ADDRESS",
        [0xC0000286] = "MAGAZINE NOT PRESENT",
        [0xC0000287] = "REINITIALIZATION NEEDED",
        [0xC000028A] = "ENCRYPTION FAILED",
        [0xC000028B] = "DECRYPTION FAILED",
        [0xC000028C] = "RANGE NOT FOUND",
        [0xC000028D] = "NO RECOVERY POLICY",
        [0xC000028E] = "NO EFS",
        [0xC000028F] = "WRONG EFS",
        [0xC0000290] = "NO USER KEYS",
        [0xC0000291] = "FILE NOT ENCRYPTED",
        [0xC0000292] = "NOT EXPORT FORMAT",
        [0xC0000293] = "FILE ENCRYPTED",
        [0xC0000295] = "WMI GUID NOT FOUND",
        [0xC0000296] = "WMI INSTANCE NOT FOUND",
        [0xC0000297] = "WMI ITEMID NOT FOUND",
        [0xC0000298] = "WMI TRY AGAIN",
        [0xC0000299] = "SHARED POLICY",
        [0xC000029A] = "POLICY OBJECT NOT FOUND",
        [0xC000029B] = "POLICY ONLY IN DS",
        [0xC000029C] = "VOLUME NOT UPGRADED",
        [0xC000029D] = "REMOTE STORAGE NOT ACTIVE",
        [0xC000029E] = "REMOTE STORAGE MEDIA ERROR",
        [0xC000029F] = "NO TRACKING SERVICE",
        [0xC00002A0] = "SERVER SID MISMATCH",
        [0xC00002A1] = "DS NO ATTRIBUTE OR VALUE",
        [0xC00002A2] = "DS INVALID ATTRIBUTE SYNTAX",
        [0xC00002A3] = "DS ATTRIBUTE TYPE UNDEFINED",
        [0xC00002A4] = "DS ATTRIBUTE OR VALUE EXISTS",
        [0xC00002A5] = "DS BUSY",
        [0xC00002A6] = "DS UNAVAILABLE",
        [0xC00002A7] = "DS NO RIDS ALLOCATED",
        [0xC00002A8] = "DS NO MORE RIDS",
        [0xC00002A9] = "DS INCORRECT ROLE OWNER",
        [0xC00002AA] = "DS RIDMGR INIT ERROR",
        [0xC00002AB] = "DS OBJ CLASS VIOLATION",
        [0xC00002AC] = "DS CANT ON NON LEAF",
        [0xC00002AD] = "DS CANT ON RDN",
        [0xC00002AE] = "DS CANT MOD OBJ CLASS",
        [0xC00002AF] = "DS CROSS DOM MOVE FAILED",
        [0xC00002B0] = "DS GC NOT AVAILABLE",
        [0xC00002B1] = "DIRECTORY SERVICE REQUIRED",
        [0xC00002B2] = "REPARSE ATTRIBUTE CONFLICT",
        [0xC00002B3] = "CANT ENABLE DENY ONLY",
        [0xC00002B4] = "FLOAT MULTIPLE FAULTS",
        [0xC00002B5] = "FLOAT MULTIPLE TRAPS",
        [0xC00002B6] = "DEVICE REMOVED",
        [0xC00002B7] = "JOURNAL DELETE IN PROGRESS",
        [0xC00002B8] = "JOURNAL NOT ACTIVE",
        [0xC00002B9] = "NOINTERFACE",
        [0xC00002C1] = "DS ADMIN LIMIT EXCEEDED",
        [0xC00002C2] = "DRIVER FAILED SLEEP",
        [0xC00002C3] = "MUTUAL AUTHENTICATION FAILED",
        [0xC00002C4] = "CORRUPT SYSTEM FILE",
        [0xC00002C5] = "DATATYPE MISALIGNMENT ERROR",
        [0xC00002C6] = "WMI READ ONLY",
        [0xC00002C7] = "WMI SET FAILURE",
        [0xC00002C8] = "COMMITMENT MINIMUM",
        [0xC00002C9] = "REG NAT CONSUMPTION",
        [0xC00002CA] = "TRANSPORT FULL",
        [0xC00002CB] = "DS SAM INIT FAILURE",
        [0xC00002CC] = "ONLY IF CONNECTED",
        [0xC00002CD] = "DS SENSITIVE GROUP VIOLATION",
        [0xC00002CE] = "PNP RESTART ENUMERATION",
        [0xC00002CF] = "JOURNAL ENTRY DELETED",
        [0xC00002D0] = "DS CANT MOD PRIMARYGROUPID",
        [0xC00002D1] = "SYSTEM IMAGE BAD SIGNATURE",
        [0xC00002D2] = "PNP REBOOT REQUIRED",
        [0xC00002D3] = "POWER STATE INVALID",
        [0xC00002D4] = "DS INVALID GROUP TYPE",
        [0xC00002D5] = "DS NO NEST GLOBALGROUP IN MIXEDDOMAIN",
        [0xC00002D6] = "DS NO NEST LOCALGROUP IN MIXEDDOMAIN",
        [0xC00002D7] = "DS GLOBAL CANT HAVE LOCAL MEMBER",
        [0xC00002D8] = "DS GLOBAL CANT HAVE UNIVERSAL MEMBER",
        [0xC00002D9] = "DS UNIVERSAL CANT HAVE LOCAL MEMBER",
        [0xC00002DA] = "DS GLOBAL CANT HAVE CROSSDOMAIN MEMBER",
        [0xC00002DB] = "DS LOCAL CANT HAVE CROSSDOMAIN LOCAL MEMBER",
        [0xC00002DC] = "DS HAVE PRIMARY MEMBERS",
        [0xC00002DD] = "WMI NOT SUPPORTED",
        [0xC00002DE] = "INSUFFICIENT POWER",
        [0xC00002DF] = "SAM NEED BOOTKEY PASSWORD",
        [0xC00002E0] = "SAM NEED BOOTKEY FLOPPY",
        [0xC00002E1] = "DS CANT START",
        [0xC00002E2] = "DS INIT FAILURE",
        [0xC00002E3] = "SAM INIT FAILURE",
        [0xC00002E4] = "DS GC REQUIRED",
        [0xC00002E5] = "DS LOCAL MEMBER OF LOCAL ONLY",
        [0xC00002E6] = "DS NO FPO IN UNIVERSAL GROUPS",
        [0xC00002E7] = "DS MACHINE ACCOUNT QUOTA EXCEEDED",
        [0xC00002E9] = "CURRENT DOMAIN NOT ALLOWED",
        [0xC00002EA] = "CANNOT MAKE",
        [0xC00002EB] = "SYSTEM SHUTDOWN",
        [0xC00002EC] = "DS INIT FAILURE CONSOLE",
        [0xC00002ED] = "DS SAM INIT FAILURE CONSOLE",
        [0xC00002EE] = "UNFINISHED CONTEXT DELETED",
        [0xC00002EF] = "NO TGT REPLY",
        [0xC00002F0] = "OBJECTID NOT FOUND",
        [0xC00002F1] = "NO IP ADDRESSES",
        [0xC00002F2] = "WRONG CREDENTIAL HANDLE",
        [0xC00002F3] = "CRYPTO SYSTEM INVALID",
        [0xC00002F4] = "MAX REFERRALS EXCEEDED",
        [0xC00002F5] = "MUST BE KDC",
        [0xC00002F6] = "STRONG CRYPTO NOT SUPPORTED",
        [0xC00002F7] = "TOO MANY PRINCIPALS",
        [0xC00002F8] = "NO PA DATA",
        [0xC00002F9] = "PKINIT NAME MISMATCH",
        [0xC00002FA] = "SMARTCARD LOGON REQUIRED",
        [0xC00002FB] = "KDC INVALID REQUEST",
        [0xC00002FC] = "KDC UNABLE TO REFER",
        [0xC00002FD] = "KDC UNKNOWN ETYPE",
        [0xC00002FE] = "SHUTDOWN IN PROGRESS",
        [0xC00002FF] = "SERVER SHUTDOWN IN PROGRESS",
        [0xC0000300] = "NOT SUPPORTED ON SBS",
        [0xC0000301] = "WMI GUID DISCONNECTED",
        [0xC0000302] = "WMI ALREADY DISABLED",
        [0xC0000303] = "WMI ALREADY ENABLED",
        [0xC0000304] = "MFT TOO FRAGMENTED",
        [0xC0000305] = "COPY PROTECTION FAILURE",
        [0xC0000306] = "CSS AUTHENTICATION FAILURE",
        [0xC0000307] = "CSS KEY NOT PRESENT",
        [0xC0000308] = "CSS KEY NOT ESTABLISHED",
        [0xC0000309] = "CSS SCRAMBLED SECTOR",
        [0xC000030A] = "CSS REGION MISMATCH",
        [0xC000030B] = "CSS RESETS EXHAUSTED",
        [0xC0000320] = "PKINIT FAILURE",
        [0xC0000321] = "SMARTCARD SUBSYSTEM FAILURE",
        [0xC0000322] = "NO KERB KEY",
        [0xC0000350] = "HOST DOWN",
        [0xC0000351] = "UNSUPPORTED PREAUTH",
        [0xC0000352] = "EFS ALG BLOB TOO BIG",
        [0xC0000353] = "PORT NOT SET",
        [0xC0000355] = "DS VERSION CHECK FAILURE",
        [0xC0000356] = "AUDITING DISABLED",
        [0xC0000357] = "PRENT4 MACHINE ACCOUNT",
        [0xC0000358] = "DS AG CANT HAVE UNIVERSAL MEMBER",
        [0xC0000359] = "INVALID IMAGE WIN 32",
        [0xC000035A] = "INVALID IMAGE WIN 64",
        [0xC000035B] = "BAD BINDINGS",
        [0xC000035C] = "NETWORK SESSION EXPIRED",
        [0xC000035D] = "APPHELP BLOCK",
        [0xC000035E] = "ALL SIDS FILTERED",
        [0xC000035F] = "NOT SAFE MODE DRIVER",
        [0xC0000361] = "ACCESS DISABLED BY POLICY DEFAULT",
        [0xC0000362] = "ACCESS DISABLED BY POLICY PATH",
        [0xC0000363] = "ACCESS DISABLED BY POLICY PUBLISHER",
        [0xC0000364] = "ACCESS DISABLED BY POLICY OTHER",
        [0xC0000365] = "FAILED DRIVER ENTRY",
        [0xC0000366] = "DEVICE ENUMERATION ERROR",
        [0xC0000368] = "MOUNT POINT NOT RESOLVED",
        [0xC0000369] = "INVALID DEVICE OBJECT PARAMETER",
        [0xC000036A] = "MCA OCCURED",
        [0xC000036B] = "DRIVER BLOCKED CRITICAL",
        [0xC000036C] = "DRIVER BLOCKED",
        [0xC000036D] = "DRIVER DATABASE ERROR",
        [0xC000036E] = "SYSTEM HIVE TOO LARGE",
        [0xC000036F] = "INVALID IMPORT OF NON DLL",
        [0xC0000371] = "NO SECRETS",
        [0xC0000372] = "ACCESS DISABLED NO SAFER UI BY POLICY",
        [0xC0000373] = "FAILED STACK SWITCH",
        [0xC0000374] = "HEAP CORRUPTION",
        [0xC0000380] = "SMARTCARD WRONG PIN",
        [0xC0000381] = "SMARTCARD CARD BLOCKED",
        [0xC0000382] = "SMARTCARD CARD NOT AUTHENTICATED",
        [0xC0000383] = "SMARTCARD NO CARD",
        [0xC0000384] = "SMARTCARD NO KEY CONTAINER",
        [0xC0000385] = "SMARTCARD NO CERTIFICATE",
        [0xC0000386] = "SMARTCARD NO KEYSET",
        [0xC0000387] = "SMARTCARD IO ERROR",
        [0xC0000388] = "DOWNGRADE DETECTED",
        [0xC0000389] = "SMARTCARD CERT REVOKED",
        [0xC000038A] = "ISSUING CA UNTRUSTED",
        [0xC000038B] = "REVOCATION OFFLINE C",
        [0xC000038C] = "PKINIT CLIENT FAILURE",
        [0xC000038D] = "SMARTCARD CERT EXPIRED",
        [0xC000038E] = "DRIVER FAILED PRIOR UNLOAD",
        [0xC000038F] = "SMARTCARD SILENT CONTEXT",
        [0xC0000401] = "PER USER TRUST QUOTA EXCEEDED",
        [0xC0000402] = "ALL USER TRUST QUOTA EXCEEDED",
        [0xC0000403] = "USER DELETE TRUST QUOTA EXCEEDED",
        [0xC0000404] = "DS NAME NOT UNIQUE",
        [0xC0000405] = "DS DUPLICATE ID FOUND",
        [0xC0000406] = "DS GROUP CONVERSION ERROR",
        [0xC0000407] = "VOLSNAP PREPARE HIBERNATE",
        [0xC0000408] = "USER2USER REQUIRED",
        [0xC0000409] = "STACK BUFFER OVERRUN",
        [0xC000040A] = "NO S4U PROT SUPPORT",
        [0xC000040B] = "CROSSREALM DELEGATION FAILURE",
        [0xC000040C] = "REVOCATION OFFLINE KDC",
        [0xC000040D] = "ISSUING CA UNTRUSTED KDC",
        [0xC000040E] = "KDC CERT EXPIRED",
        [0xC000040F] = "KDC CERT REVOKED",
        [0xC0000410] = "PARAMETER QUOTA EXCEEDED",
        [0xC0000411] = "HIBERNATION FAILURE",
        [0xC0000412] = "DELAY LOAD FAILED",
        [0xC0000413] = "AUTHENTICATION FIREWALL FAILED",
        [0xC0000414] = "VDM DISALLOWED",
        [0xC0000415] = "HUNG DISPLAY DRIVER THREAD",
        [0xC0000416] = "INSUFFICIENT RESOURCE FOR SPECIFIED SHARED SECTION SIZE",
        [0xC0000417] = "INVALID CRUNTIME PARAMETER",
        [0xC0000418] = "NTLM BLOCKED",
        [0xC0000419] = "DS SRC SID EXISTS IN FOREST",
        [0xC000041A] = "DS DOMAIN NAME EXISTS IN FOREST",
        [0xC000041B] = "DS FLAT NAME EXISTS IN FOREST",
        [0xC000041C] = "INVALID USER PRINCIPAL NAME",
        [0xC0000420] = "ASSERTION FAILURE",
        [0xC0000421] = "VERIFIER STOP",
        [0xC0000423] = "CALLBACK POP STACK",
        [0xC0000424] = "INCOMPATIBLE DRIVER BLOCKED",
        [0xC0000425] = "HIVE UNLOADED",
        [0xC0000426] = "COMPRESSION DISABLED",
        [0xC0000427] = "FILE SYSTEM LIMITATION",
        [0xC0000428] = "INVALID IMAGE HASH",
        [0xC0000429] = "NOT CAPABLE",
        [0xC000042A] = "REQUEST OUT OF SEQUENCE",
        [0xC000042B] = "IMPLEMENTATION LIMIT",
        [0xC000042C] = "ELEVATION REQUIRED",
        [0xC000042D] = "NO SECURITY CONTEXT",
        [0xC000042E] = "PKU2U CERT FAILURE",
        [0xC0000432] = "BEYOND VDL",
        [0xC0000433] = "ENCOUNTERED WRITE IN PROGRESS",
        [0xC0000434] = "PTE CHANGED",
        [0xC0000435] = "PURGE FAILED",
        [0xC0000440] = "CRED REQUIRES CONFIRMATION",
        [0xC0000441] = "CS ENCRYPTION INVALID SERVER RESPONSE",
        [0xC0000442] = "CS ENCRYPTION UNSUPPORTED SERVER",
        [0xC0000443] = "CS ENCRYPTION EXISTING ENCRYPTED FILE",
        [0xC0000444] = "CS ENCRYPTION NEW ENCRYPTED FILE",
        [0xC0000445] = "CS ENCRYPTION FILE NOT CSE",
        [0xC0000446] = "INVALID LABEL",
        [0xC0000450] = "DRIVER PROCESS TERMINATED",
        [0xC0000451] = "AMBIGUOUS SYSTEM DEVICE",
        [0xC0000452] = "SYSTEM DEVICE NOT FOUND",
        [0xC0000453] = "RESTART BOOT APPLICATION",
        [0xC0000454] = "INSUFFICIENT NVRAM RESOURCES",
        [0xC0000500] = "INVALID TASK NAME",
        [0xC0000501] = "INVALID TASK INDEX",
        [0xC0000502] = "THREAD ALREADY IN TASK",
        [0xC0000503] = "CALLBACK BYPASS",
        [0xC0000602] = "FAIL FAST EXCEPTION",
        [0xC0000603] = "IMAGE CERT REVOKED",
        [0xC0000700] = "PORT CLOSED",
        [0xC0000701] = "MESSAGE LOST",
        [0xC0000702] = "INVALID MESSAGE",
        [0xC0000703] = "REQUEST CANCELED",
        [0xC0000704] = "RECURSIVE DISPATCH",
        [0xC0000705] = "LPC RECEIVE BUFFER EXPECTED",
        [0xC0000706] = "LPC INVALID CONNECTION USAGE",
        [0xC0000707] = "LPC REQUESTS NOT ALLOWED",
        [0xC0000708] = "RESOURCE IN USE",
        [0xC0000709] = "HARDWARE MEMORY ERROR",
        [0xC000070A] = "THREADPOOL HANDLE EXCEPTION",
        [0xC000070B] = "THREADPOOL SET EVENT ON COMPLETION FAILED",
        [0xC000070C] = "THREADPOOL RELEASE SEMAPHORE ON COMPLETION FAILED",
        [0xC000070D] = "THREADPOOL RELEASE MUTEX ON COMPLETION FAILED",
        [0xC000070E] = "THREADPOOL FREE LIBRARY ON COMPLETION FAILED",
        [0xC000070F] = "THREADPOOL RELEASED DURING OPERATION",
        [0xC0000710] = "CALLBACK RETURNED WHILE IMPERSONATING",
        [0xC0000711] = "APC RETURNED WHILE IMPERSONATING",
        [0xC0000712] = "PROCESS IS PROTECTED",
        [0xC0000713] = "MCA EXCEPTION",
        [0xC0000714] = "CERTIFICATE MAPPING NOT UNIQUE",
        [0xC0000715] = "SYMLINK CLASS DISABLED",
        [0xC0000716] = "INVALID IDN NORMALIZATION",
        [0xC0000717] = "NO UNICODE TRANSLATION",
        [0xC0000718] = "ALREADY REGISTERED",
        [0xC0000719] = "CONTEXT MISMATCH",
        [0xC000071A] = "PORT ALREADY HAS COMPLETION LIST",
        [0xC000071B] = "CALLBACK RETURNED THREAD PRIORITY",
        [0xC000071C] = "INVALID THREAD",
        [0xC000071D] = "CALLBACK RETURNED TRANSACTION",
        [0xC000071E] = "CALLBACK RETURNED LDR LOCK",
        [0xC000071F] = "CALLBACK RETURNED LANG",
        [0xC0000720] = "CALLBACK RETURNED PRI BACK",
        [0xC0000800] = "DISK REPAIR DISABLED",
        [0xC0000801] = "DS DOMAIN RENAME IN PROGRESS",
        [0xC0000802] = "DISK QUOTA EXCEEDED",
        [0xC0000804] = "CONTENT BLOCKED",
        [0xC0000805] = "BAD CLUSTERS",
        [0xC0000806] = "VOLUME DIRTY",
        [0xC0000901] = "FILE CHECKED OUT",
        [0xC0000902] = "CHECKOUT REQUIRED",
        [0xC0000903] = "BAD FILE TYPE",
        [0xC0000904] = "FILE TOO LARGE",
        [0xC0000905] = "FORMS AUTH REQUIRED",
        [0xC0000906] = "VIRUS INFECTED",
        [0xC0000907] = "VIRUS DELETED",
        [0xC0000908] = "BAD MCFG TABLE",
        [0xC0000909] = "CANNOT BREAK OPLOCK",
        [0xC0009898] = "WOW ASSERTION",
        [0xC000A000] = "INVALID SIGNATURE",
        [0xC000A001] = "HMAC NOT SUPPORTED",
        [0xC000A010] = "IPSEC QUEUE OVERFLOW",
        [0xC000A011] = "ND QUEUE OVERFLOW",
        [0xC000A012] = "HOPLIMIT EXCEEDED",
        [0xC000A013] = "PROTOCOL NOT SUPPORTED",
        [0xC000A080] = "LOST WRITEBEHIND DATA NETWORK DISCONNECTED",
        [0xC000A081] = "LOST WRITEBEHIND DATA NETWORK SERVER ERROR",
        [0xC000A082] = "LOST WRITEBEHIND DATA LOCAL DISK ERROR",
        [0xC000A083] = "XML PARSE ERROR",
        [0xC000A084] = "XMLDSIG ERROR",
        [0xC000A085] = "WRONG COMPARTMENT",
        [0xC000A086] = "AUTHIP FAILURE",
        [0xC000A087] = "DS OID MAPPED GROUP CANT HAVE MEMBERS",
        [0xC000A088] = "DS OID NOT FOUND",
        [0xC000A100] = "HASH NOT SUPPORTED",
        [0xC000A101] = "HASH NOT PRESENT",
        [0xC0010001] = "DBG NO STATE CHANGE",
        [0xC0010002] = "DBG APP NOT IDLE",
        [0xC0020001] = "RPC NT INVALID STRING BINDING",
        [0xC0020002] = "RPC NT WRONG KIND OF BINDING",
        [0xC0020003] = "RPC NT INVALID BINDING",
        [0xC0020004] = "RPC NT PROTSEQ NOT SUPPORTED",
        [0xC0020005] = "RPC NT INVALID RPC PROTSEQ",
        [0xC0020006] = "RPC NT INVALID STRING UUID",
        [0xC0020007] = "RPC NT INVALID ENDPOINT FORMAT",
        [0xC0020008] = "RPC NT INVALID NET ADDR",
        [0xC0020009] = "RPC NT NO ENDPOINT FOUND",
        [0xC002000A] = "RPC NT INVALID TIMEOUT",
        [0xC002000B] = "RPC NT OBJECT NOT FOUND",
        [0xC002000C] = "RPC NT ALREADY REGISTERED",
        [0xC002000D] = "RPC NT TYPE ALREADY REGISTERED",
        [0xC002000E] = "RPC NT ALREADY LISTENING",
        [0xC002000F] = "RPC NT NO PROTSEQS REGISTERED",
        [0xC0020010] = "RPC NT NOT LISTENING",
        [0xC0020011] = "RPC NT UNKNOWN MGR TYPE",
        [0xC0020012] = "RPC NT UNKNOWN IF",
        [0xC0020013] = "RPC NT NO BINDINGS",
        [0xC0020014] = "RPC NT NO PROTSEQS",
        [0xC0020015] = "RPC NT CANT CREATE ENDPOINT",
        [0xC0020016] = "RPC NT OUT OF RESOURCES",
        [0xC0020017] = "RPC NT SERVER UNAVAILABLE",
        [0xC0020018] = "RPC NT SERVER TOO BUSY",
        [0xC0020019] = "RPC NT INVALID NETWORK OPTIONS",
        [0xC002001A] = "RPC NT NO CALL ACTIVE",
        [0xC002001B] = "RPC NT CALL FAILED",
        [0xC002001C] = "RPC NT CALL FAILED DNE",
        [0xC002001D] = "RPC NT PROTOCOL ERROR",
        [0xC002001F] = "RPC NT UNSUPPORTED TRANS SYN",
        [0xC0020021] = "RPC NT UNSUPPORTED TYPE",
        [0xC0020022] = "RPC NT INVALID TAG",
        [0xC0020023] = "RPC NT INVALID BOUND",
        [0xC0020024] = "RPC NT NO ENTRY NAME",
        [0xC0020025] = "RPC NT INVALID NAME SYNTAX",
        [0xC0020026] = "RPC NT UNSUPPORTED NAME SYNTAX",
        [0xC0020028] = "RPC NT UUID NO ADDRESS",
        [0xC0020029] = "RPC NT DUPLICATE ENDPOINT",
        [0xC002002A] = "RPC NT UNKNOWN AUTHN TYPE",
        [0xC002002B] = "RPC NT MAX CALLS TOO SMALL",
        [0xC002002C] = "RPC NT STRING TOO LONG",
        [0xC002002D] = "RPC NT PROTSEQ NOT FOUND",
        [0xC002002E] = "RPC NT PROCNUM OUT OF RANGE",
        [0xC002002F] = "RPC NT BINDING HAS NO AUTH",
        [0xC0020030] = "RPC NT UNKNOWN AUTHN SERVICE",
        [0xC0020031] = "RPC NT UNKNOWN AUTHN LEVEL",
        [0xC0020032] = "RPC NT INVALID AUTH IDENTITY",
        [0xC0020033] = "RPC NT UNKNOWN AUTHZ SERVICE",
        [0xC0020034] = "EPT NT INVALID ENTRY",
        [0xC0020035] = "EPT NT CANT PERFORM OP",
        [0xC0020036] = "EPT NT NOT REGISTERED",
        [0xC0020037] = "RPC NT NOTHING TO EXPORT",
        [0xC0020038] = "RPC NT INCOMPLETE NAME",
        [0xC0020039] = "RPC NT INVALID VERS OPTION",
        [0xC002003A] = "RPC NT NO MORE MEMBERS",
        [0xC002003B] = "RPC NT NOT ALL OBJS UNEXPORTED",
        [0xC002003C] = "RPC NT INTERFACE NOT FOUND",
        [0xC002003D] = "RPC NT ENTRY ALREADY EXISTS",
        [0xC002003E] = "RPC NT ENTRY NOT FOUND",
        [0xC002003F] = "RPC NT NAME SERVICE UNAVAILABLE",
        [0xC0020040] = "RPC NT INVALID NAF ID",
        [0xC0020041] = "RPC NT CANNOT SUPPORT",
        [0xC0020042] = "RPC NT NO CONTEXT AVAILABLE",
        [0xC0020043] = "RPC NT INTERNAL ERROR",
        [0xC0020044] = "RPC NT ZERO DIVIDE",
        [0xC0020045] = "RPC NT ADDRESS ERROR",
        [0xC0020046] = "RPC NT FP DIV ZERO",
        [0xC0020047] = "RPC NT FP UNDERFLOW",
        [0xC0020048] = "RPC NT FP OVERFLOW",
        [0xC0020049] = "RPC NT CALL IN PROGRESS",
        [0xC002004A] = "RPC NT NO MORE BINDINGS",
        [0xC002004B] = "RPC NT GROUP MEMBER NOT FOUND",
        [0xC002004C] = "EPT NT CANT CREATE",
        [0xC002004D] = "RPC NT INVALID OBJECT",
        [0xC002004F] = "RPC NT NO INTERFACES",
        [0xC0020050] = "RPC NT CALL CANCELLED",
        [0xC0020051] = "RPC NT BINDING INCOMPLETE",
        [0xC0020052] = "RPC NT COMM FAILURE",
        [0xC0020053] = "RPC NT UNSUPPORTED AUTHN LEVEL",
        [0xC0020054] = "RPC NT NO PRINC NAME",
        [0xC0020055] = "RPC NT NOT RPC ERROR",
        [0xC0020057] = "RPC NT SEC PKG ERROR",
        [0xC0020058] = "RPC NT NOT CANCELLED",
        [0xC0020062] = "RPC NT INVALID ASYNC HANDLE",
        [0xC0020063] = "RPC NT INVALID ASYNC CALL",
        [0xC0020064] = "RPC NT PROXY ACCESS DENIED",
        [0xC0030001] = "RPC NT NO MORE ENTRIES",
        [0xC0030002] = "RPC NT SS CHAR TRANS OPEN FAIL",
        [0xC0030003] = "RPC NT SS CHAR TRANS SHORT FILE",
        [0xC0030004] = "RPC NT SS IN NULL CONTEXT",
        [0xC0030005] = "RPC NT SS CONTEXT MISMATCH",
        [0xC0030006] = "RPC NT SS CONTEXT DAMAGED",
        [0xC0030007] = "RPC NT SS HANDLES MISMATCH",
        [0xC0030008] = "RPC NT SS CANNOT GET CALL HANDLE",
        [0xC0030009] = "RPC NT NULL REF POINTER",
        [0xC003000A] = "RPC NT ENUM VALUE OUT OF RANGE",
        [0xC003000B] = "RPC NT BYTE COUNT TOO SMALL",
        [0xC003000C] = "RPC NT BAD STUB DATA",
        [0xC0030059] = "RPC NT INVALID ES ACTION",
        [0xC003005A] = "RPC NT WRONG ES VERSION",
        [0xC003005B] = "RPC NT WRONG STUB VERSION",
        [0xC003005C] = "RPC NT INVALID PIPE OBJECT",
        [0xC003005D] = "RPC NT INVALID PIPE OPERATION",
        [0xC003005E] = "RPC NT WRONG PIPE VERSION",
        [0xC003005F] = "RPC NT PIPE CLOSED",
        [0xC0030060] = "RPC NT PIPE DISCIPLINE ERROR",
        [0xC0030061] = "RPC NT PIPE EMPTY",
        [0xC0040035] = "PNP BAD MPS TABLE",
        [0xC0040036] = "PNP TRANSLATION FAILED",
        [0xC0040037] = "PNP IRQ TRANSLATION FAILED",
        [0xC0040038] = "PNP INVALID ID",
        [0xC0040039] = "IO REISSUE AS CACHED",
        [0xC00A0001] = "CTX WINSTATION NAME INVALID",
        [0xC00A0002] = "CTX INVALID PD",
        [0xC00A0003] = "CTX PD NOT FOUND",
        [0xC00A0006] = "CTX CLOSE PENDING",
        [0xC00A0007] = "CTX NO OUTBUF",
        [0xC00A0008] = "CTX MODEM INF NOT FOUND",
        [0xC00A0009] = "CTX INVALID MODEMNAME",
        [0xC00A000A] = "CTX RESPONSE ERROR",
        [0xC00A000B] = "CTX MODEM RESPONSE TIMEOUT",
        [0xC00A000C] = "CTX MODEM RESPONSE NO CARRIER",
        [0xC00A000D] = "CTX MODEM RESPONSE NO DIALTONE",
        [0xC00A000E] = "CTX MODEM RESPONSE BUSY",
        [0xC00A000F] = "CTX MODEM RESPONSE VOICE",
        [0xC00A0010] = "CTX TD ERROR",
        [0xC00A0012] = "CTX LICENSE CLIENT INVALID",
        [0xC00A0013] = "CTX LICENSE NOT AVAILABLE",
        [0xC00A0014] = "CTX LICENSE EXPIRED",
        [0xC00A0015] = "CTX WINSTATION NOT FOUND",
        [0xC00A0016] = "CTX WINSTATION NAME COLLISION",
        [0xC00A0017] = "CTX WINSTATION BUSY",
        [0xC00A0018] = "CTX BAD VIDEO MODE",
        [0xC00A0022] = "CTX GRAPHICS INVALID",
        [0xC00A0024] = "CTX NOT CONSOLE",
        [0xC00A0026] = "CTX CLIENT QUERY TIMEOUT",
        [0xC00A0027] = "CTX CONSOLE DISCONNECT",
        [0xC00A0028] = "CTX CONSOLE CONNECT",
        [0xC00A002A] = "CTX SHADOW DENIED",
        [0xC00A002B] = "CTX WINSTATION ACCESS DENIED",
        [0xC00A002E] = "CTX INVALID WD",
        [0xC00A002F] = "CTX WD NOT FOUND",
        [0xC00A0030] = "CTX SHADOW INVALID",
        [0xC00A0031] = "CTX SHADOW DISABLED",
        [0xC00A0032] = "RDP PROTOCOL ERROR",
        [0xC00A0033] = "CTX CLIENT LICENSE NOT SET",
        [0xC00A0034] = "CTX CLIENT LICENSE IN USE",
        [0xC00A0035] = "CTX SHADOW ENDED BY MODE CHANGE",
        [0xC00A0036] = "CTX SHADOW NOT RUNNING",
        [0xC00A0037] = "CTX LOGON DISABLED",
        [0xC00A0038] = "CTX SECURITY LAYER ERROR",
        [0xC00A0039] = "TS INCOMPATIBLE SESSIONS",
        [0xC00B0001] = "MUI FILE NOT FOUND",
        [0xC00B0002] = "MUI INVALID FILE",
        [0xC00B0003] = "MUI INVALID RC CONFIG",
        [0xC00B0004] = "MUI INVALID LOCALE NAME",
        [0xC00B0005] = "MUI INVALID ULTIMATEFALLBACK NAME",
        [0xC00B0006] = "MUI FILE NOT LOADED",
        [0xC00B0007] = "RESOURCE ENUM USER STOP",
        [0xC0130001] = "CLUSTER INVALID NODE",
        [0xC0130002] = "CLUSTER NODE EXISTS",
        [0xC0130003] = "CLUSTER JOIN IN PROGRESS",
        [0xC0130004] = "CLUSTER NODE NOT FOUND",
        [0xC0130005] = "CLUSTER LOCAL NODE NOT FOUND",
        [0xC0130006] = "CLUSTER NETWORK EXISTS",
        [0xC0130007] = "CLUSTER NETWORK NOT FOUND",
        [0xC0130008] = "CLUSTER NETINTERFACE EXISTS",
        [0xC0130009] = "CLUSTER NETINTERFACE NOT FOUND",
        [0xC013000A] = "CLUSTER INVALID REQUEST",
        [0xC013000B] = "CLUSTER INVALID NETWORK PROVIDER",
        [0xC013000C] = "CLUSTER NODE DOWN",
        [0xC013000D] = "CLUSTER NODE UNREACHABLE",
        [0xC013000E] = "CLUSTER NODE NOT MEMBER",
        [0xC013000F] = "CLUSTER JOIN NOT IN PROGRESS",
        [0xC0130010] = "CLUSTER INVALID NETWORK",
        [0xC0130011] = "CLUSTER NO NET ADAPTERS",
        [0xC0130012] = "CLUSTER NODE UP",
        [0xC0130013] = "CLUSTER NODE PAUSED",
        [0xC0130014] = "CLUSTER NODE NOT PAUSED",
        [0xC0130015] = "CLUSTER NO SECURITY CONTEXT",
        [0xC0130016] = "CLUSTER NETWORK NOT INTERNAL",
        [0xC0130017] = "CLUSTER POISONED",
        [0xC0140001] = "ACPI INVALID OPCODE",
        [0xC0140002] = "ACPI STACK OVERFLOW",
        [0xC0140003] = "ACPI ASSERT FAILED",
        [0xC0140004] = "ACPI INVALID INDEX",
        [0xC0140005] = "ACPI INVALID ARGUMENT",
        [0xC0140006] = "ACPI FATAL",
        [0xC0140007] = "ACPI INVALID SUPERNAME",
        [0xC0140008] = "ACPI INVALID ARGTYPE",
        [0xC0140009] = "ACPI INVALID OBJTYPE",
        [0xC014000A] = "ACPI INVALID TARGETTYPE",
        [0xC014000B] = "ACPI INCORRECT ARGUMENT COUNT",
        [0xC014000C] = "ACPI ADDRESS NOT MAPPED",
        [0xC014000D] = "ACPI INVALID EVENTTYPE",
        [0xC014000E] = "ACPI HANDLER COLLISION",
        [0xC014000F] = "ACPI INVALID DATA",
        [0xC0140010] = "ACPI INVALID REGION",
        [0xC0140011] = "ACPI INVALID ACCESS SIZE",
        [0xC0140012] = "ACPI ACQUIRE GLOBAL LOCK",
        [0xC0140013] = "ACPI ALREADY INITIALIZED",
        [0xC0140014] = "ACPI NOT INITIALIZED",
        [0xC0140015] = "ACPI INVALID MUTEX LEVEL",
        [0xC0140016] = "ACPI MUTEX NOT OWNED",
        [0xC0140017] = "ACPI MUTEX NOT OWNER",
        [0xC0140018] = "ACPI RS ACCESS",
        [0xC0140019] = "ACPI INVALID TABLE",
        [0xC0140020] = "ACPI REG HANDLER FAILED",
        [0xC0140021] = "ACPI POWER REQUEST FAILED",
        [0xC0150001] = "SXS SECTION NOT FOUND",
        [0xC0150002] = "SXS CANT GEN ACTCTX",
        [0xC0150003] = "SXS INVALID ACTCTXDATA FORMAT",
        [0xC0150004] = "SXS ASSEMBLY NOT FOUND",
        [0xC0150005] = "SXS MANIFEST FORMAT ERROR",
        [0xC0150006] = "SXS MANIFEST PARSE ERROR",
        [0xC0150007] = "SXS ACTIVATION CONTEXT DISABLED",
        [0xC0150008] = "SXS KEY NOT FOUND",
        [0xC0150009] = "SXS VERSION CONFLICT",
        [0xC015000A] = "SXS WRONG SECTION TYPE",
        [0xC015000B] = "SXS THREAD QUERIES DISABLED",
        [0xC015000C] = "SXS ASSEMBLY MISSING",
        [0xC015000E] = "SXS PROCESS DEFAULT ALREADY SET",
        [0xC015000F] = "SXS EARLY DEACTIVATION",
        [0xC0150010] = "SXS INVALID DEACTIVATION",
        [0xC0150011] = "SXS MULTIPLE DEACTIVATION",
        [0xC0150012] = "SXS SYSTEM DEFAULT ACTIVATION CONTEXT EMPTY",
        [0xC0150013] = "SXS PROCESS TERMINATION REQUESTED",
        [0xC0150014] = "SXS CORRUPT ACTIVATION STACK",
        [0xC0150015] = "SXS CORRUPTION",
        [0xC0150016] = "SXS INVALID IDENTITY ATTRIBUTE VALUE",
        [0xC0150017] = "SXS INVALID IDENTITY ATTRIBUTE NAME",
        [0xC0150018] = "SXS IDENTITY DUPLICATE ATTRIBUTE",
        [0xC0150019] = "SXS IDENTITY PARSE ERROR",
        [0xC015001A] = "SXS COMPONENT STORE CORRUPT",
        [0xC015001B] = "SXS FILE HASH MISMATCH",
        [0xC015001C] = "SXS MANIFEST IDENTITY SAME BUT CONTENTS DIFFERENT",
        [0xC015001D] = "SXS IDENTITIES DIFFERENT",
        [0xC015001E] = "SXS ASSEMBLY IS NOT A DEPLOYMENT",
        [0xC015001F] = "SXS FILE NOT PART OF ASSEMBLY",
        [0xC0150020] = "ADVANCED INSTALLER FAILED",
        [0xC0150021] = "XML ENCODING MISMATCH",
        [0xC0150022] = "SXS MANIFEST TOO BIG",
        [0xC0150023] = "SXS SETTING NOT REGISTERED",
        [0xC0150024] = "SXS TRANSACTION CLOSURE INCOMPLETE",
        [0xC0150025] = "SMI PRIMITIVE INSTALLER FAILED",
        [0xC0150026] = "GENERIC COMMAND FAILED",
        [0xC0150027] = "SXS FILE HASH MISSING",
        [0xC0190001] = "TRANSACTIONAL CONFLICT",
        [0xC0190002] = "INVALID TRANSACTION",
        [0xC0190003] = "TRANSACTION NOT ACTIVE",
        [0xC0190004] = "TM INITIALIZATION FAILED",
        [0xC0190005] = "RM NOT ACTIVE",
        [0xC0190006] = "RM METADATA CORRUPT",
        [0xC0190007] = "TRANSACTION NOT JOINED",
        [0xC0190008] = "DIRECTORY NOT RM",
        [0xC019000A] = "TRANSACTIONS UNSUPPORTED REMOTE",
        [0xC019000B] = "LOG RESIZE INVALID SIZE",
        [0xC019000C] = "REMOTE FILE VERSION MISMATCH",
        [0xC019000F] = "CRM PROTOCOL ALREADY EXISTS",
        [0xC0190010] = "TRANSACTION PROPAGATION FAILED",
        [0xC0190011] = "CRM PROTOCOL NOT FOUND",
        [0xC0190012] = "TRANSACTION SUPERIOR EXISTS",
        [0xC0190013] = "TRANSACTION REQUEST NOT VALID",
        [0xC0190014] = "TRANSACTION NOT REQUESTED",
        [0xC0190015] = "TRANSACTION ALREADY ABORTED",
        [0xC0190016] = "TRANSACTION ALREADY COMMITTED",
        [0xC0190017] = "TRANSACTION INVALID MARSHALL BUFFER",
        [0xC0190018] = "CURRENT TRANSACTION NOT VALID",
        [0xC0190019] = "LOG GROWTH FAILED",
        [0xC0190021] = "OBJECT NO LONGER EXISTS",
        [0xC0190022] = "STREAM MINIVERSION NOT FOUND",
        [0xC0190023] = "STREAM MINIVERSION NOT VALID",
        [0xC0190024] = "MINIVERSION INACCESSIBLE FROM SPECIFIED TRANSACTION",
        [0xC0190025] = "CANT OPEN MINIVERSION WITH MODIFY INTENT",
        [0xC0190026] = "CANT CREATE MORE STREAM MINIVERSIONS",
        [0xC0190028] = "HANDLE NO LONGER VALID",
        [0xC0190030] = "LOG CORRUPTION DETECTED",
        [0xC0190032] = "RM DISCONNECTED",
        [0xC0190033] = "ENLISTMENT NOT SUPERIOR",
        [0xC0190036] = "FILE IDENTITY NOT PERSISTENT",
        [0xC0190037] = "CANT BREAK TRANSACTIONAL DEPENDENCY",
        [0xC0190038] = "CANT CROSS RM BOUNDARY",
        [0xC0190039] = "TXF DIR NOT EMPTY",
        [0xC019003A] = "INDOUBT TRANSACTIONS EXIST",
        [0xC019003B] = "TM VOLATILE",
        [0xC019003C] = "ROLLBACK TIMER EXPIRED",
        [0xC019003D] = "TXF ATTRIBUTE CORRUPT",
        [0xC019003E] = "EFS NOT ALLOWED IN TRANSACTION",
        [0xC019003F] = "TRANSACTIONAL OPEN NOT ALLOWED",
        [0xC0190040] = "TRANSACTED MAPPING UNSUPPORTED REMOTE",
        [0xC0190043] = "TRANSACTION REQUIRED PROMOTION",
        [0xC0190044] = "CANNOT EXECUTE FILE IN TRANSACTION",
        [0xC0190045] = "TRANSACTIONS NOT FROZEN",
        [0xC0190046] = "TRANSACTION FREEZE IN PROGRESS",
        [0xC0190047] = "NOT SNAPSHOT VOLUME",
        [0xC0190048] = "NO SAVEPOINT WITH OPEN FILES",
        [0xC0190049] = "SPARSE NOT ALLOWED IN TRANSACTION",
        [0xC019004A] = "TM IDENTITY MISMATCH",
        [0xC019004B] = "FLOATED SECTION",
        [0xC019004C] = "CANNOT ACCEPT TRANSACTED WORK",
        [0xC019004D] = "CANNOT ABORT TRANSACTIONS",
        [0xC019004E] = "TRANSACTION NOT FOUND",
        [0xC019004F] = "RESOURCEMANAGER NOT FOUND",
        [0xC0190050] = "ENLISTMENT NOT FOUND",
        [0xC0190051] = "TRANSACTIONMANAGER NOT FOUND",
        [0xC0190052] = "TRANSACTIONMANAGER NOT ONLINE",
        [0xC0190053] = "TRANSACTIONMANAGER RECOVERY NAME COLLISION",
        [0xC0190054] = "TRANSACTION NOT ROOT",
        [0xC0190055] = "TRANSACTION OBJECT EXPIRED",
        [0xC0190056] = "COMPRESSION NOT ALLOWED IN TRANSACTION",
        [0xC0190057] = "TRANSACTION RESPONSE NOT ENLISTED",
        [0xC0190058] = "TRANSACTION RECORD TOO LONG",
        [0xC0190059] = "NO LINK TRACKING IN TRANSACTION",
        [0xC019005A] = "OPERATION NOT SUPPORTED IN TRANSACTION",
        [0xC019005B] = "TRANSACTION INTEGRITY VIOLATED",
        [0xC0190060] = "EXPIRED HANDLE",
        [0xC0190061] = "TRANSACTION NOT ENLISTED",
        [0xC01A0001] = "LOG SECTOR INVALID",
        [0xC01A0002] = "LOG SECTOR PARITY INVALID",
        [0xC01A0003] = "LOG SECTOR REMAPPED",
        [0xC01A0004] = "LOG BLOCK INCOMPLETE",
        [0xC01A0005] = "LOG INVALID RANGE",
        [0xC01A0006] = "LOG BLOCKS EXHAUSTED",
        [0xC01A0007] = "LOG READ CONTEXT INVALID",
        [0xC01A0008] = "LOG RESTART INVALID",
        [0xC01A0009] = "LOG BLOCK VERSION",
        [0xC01A000A] = "LOG BLOCK INVALID",
        [0xC01A000B] = "LOG READ MODE INVALID",
        [0xC01A000D] = "LOG METADATA CORRUPT",
        [0xC01A000E] = "LOG METADATA INVALID",
        [0xC01A000F] = "LOG METADATA INCONSISTENT",
        [0xC01A0010] = "LOG RESERVATION INVALID",
        [0xC01A0011] = "LOG CANT DELETE",
        [0xC01A0012] = "LOG CONTAINER LIMIT EXCEEDED",
        [0xC01A0013] = "LOG START OF LOG",
        [0xC01A0014] = "LOG POLICY ALREADY INSTALLED",
        [0xC01A0015] = "LOG POLICY NOT INSTALLED",
        [0xC01A0016] = "LOG POLICY INVALID",
        [0xC01A0017] = "LOG POLICY CONFLICT",
        [0xC01A0018] = "LOG PINNED ARCHIVE TAIL",
        [0xC01A0019] = "LOG RECORD NONEXISTENT",
        [0xC01A001A] = "LOG RECORDS RESERVED INVALID",
        [0xC01A001B] = "LOG SPACE RESERVED INVALID",
        [0xC01A001C] = "LOG TAIL INVALID",
        [0xC01A001D] = "LOG FULL",
        [0xC01A001E] = "LOG MULTIPLEXED",
        [0xC01A001F] = "LOG DEDICATED",
        [0xC01A0020] = "LOG ARCHIVE NOT IN PROGRESS",
        [0xC01A0021] = "LOG ARCHIVE IN PROGRESS",
        [0xC01A0022] = "LOG EPHEMERAL",
        [0xC01A0023] = "LOG NOT ENOUGH CONTAINERS",
        [0xC01A0024] = "LOG CLIENT ALREADY REGISTERED",
        [0xC01A0025] = "LOG CLIENT NOT REGISTERED",
        [0xC01A0026] = "LOG FULL HANDLER IN PROGRESS",
        [0xC01A0027] = "LOG CONTAINER READ FAILED",
        [0xC01A0028] = "LOG CONTAINER WRITE FAILED",
        [0xC01A0029] = "LOG CONTAINER OPEN FAILED",
        [0xC01A002A] = "LOG CONTAINER STATE INVALID",
        [0xC01A002B] = "LOG STATE INVALID",
        [0xC01A002C] = "LOG PINNED",
        [0xC01A002D] = "LOG METADATA FLUSH FAILED",
        [0xC01A002E] = "LOG INCONSISTENT SECURITY",
        [0xC01A002F] = "LOG APPENDED FLUSH FAILED",
        [0xC01A0030] = "LOG PINNED RESERVATION",
        [0xC01B00EA] = "VIDEO HUNG DISPLAY DRIVER THREAD",
        [0xC01C0001] = "FLT NO HANDLER DEFINED",
        [0xC01C0002] = "FLT CONTEXT ALREADY DEFINED",
        [0xC01C0003] = "FLT INVALID ASYNCHRONOUS REQUEST",
        [0xC01C0004] = "FLT DISALLOW FAST IO",
        [0xC01C0005] = "FLT INVALID NAME REQUEST",
        [0xC01C0006] = "FLT NOT SAFE TO POST OPERATION",
        [0xC01C0007] = "FLT NOT INITIALIZED",
        [0xC01C0008] = "FLT FILTER NOT READY",
        [0xC01C0009] = "FLT POST OPERATION CLEANUP",
        [0xC01C000A] = "FLT INTERNAL ERROR",
        [0xC01C000B] = "FLT DELETING OBJECT",
        [0xC01C000C] = "FLT MUST BE NONPAGED POOL",
        [0xC01C000D] = "FLT DUPLICATE ENTRY",
        [0xC01C000E] = "FLT CBDQ DISABLED",
        [0xC01C000F] = "FLT DO NOT ATTACH",
        [0xC01C0010] = "FLT DO NOT DETACH",
        [0xC01C0011] = "FLT INSTANCE ALTITUDE COLLISION",
        [0xC01C0012] = "FLT INSTANCE NAME COLLISION",
        [0xC01C0013] = "FLT FILTER NOT FOUND",
        [0xC01C0014] = "FLT VOLUME NOT FOUND",
        [0xC01C0015] = "FLT INSTANCE NOT FOUND",
        [0xC01C0016] = "FLT CONTEXT ALLOCATION NOT FOUND",
        [0xC01C0017] = "FLT INVALID CONTEXT REGISTRATION",
        [0xC01C0018] = "FLT NAME CACHE MISS",
        [0xC01C0019] = "FLT NO DEVICE OBJECT",
        [0xC01C001A] = "FLT VOLUME ALREADY MOUNTED",
        [0xC01C001B] = "FLT ALREADY ENLISTED",
        [0xC01C001C] = "FLT CONTEXT ALREADY LINKED",
        [0xC01C0020] = "FLT NO WAITER FOR REPLY",
        [0xC01D0001] = "MONITOR NO DESCRIPTOR",
        [0xC01D0002] = "MONITOR UNKNOWN DESCRIPTOR FORMAT",
        [0xC01D0003] = "MONITOR INVALID DESCRIPTOR CHECKSUM",
        [0xC01D0004] = "MONITOR INVALID STANDARD TIMING BLOCK",
        [0xC01D0005] = "MONITOR WMI DATABLOCK REGISTRATION FAILED",
        [0xC01D0006] = "MONITOR INVALID SERIAL NUMBER MONDSC BLOCK",
        [0xC01D0007] = "MONITOR INVALID USER FRIENDLY MONDSC BLOCK",
        [0xC01D0008] = "MONITOR NO MORE DESCRIPTOR DATA",
        [0xC01D0009] = "MONITOR INVALID DETAILED TIMING BLOCK",
        [0xC01D000A] = "MONITOR INVALID MANUFACTURE DATE",
        [0xC01E0000] = "GRAPHICS NOT EXCLUSIVE MODE OWNER",
        [0xC01E0001] = "GRAPHICS INSUFFICIENT DMA BUFFER",
        [0xC01E0002] = "GRAPHICS INVALID DISPLAY ADAPTER",
        [0xC01E0003] = "GRAPHICS ADAPTER WAS RESET",
        [0xC01E0004] = "GRAPHICS INVALID DRIVER MODEL",
        [0xC01E0005] = "GRAPHICS PRESENT MODE CHANGED",
        [0xC01E0006] = "GRAPHICS PRESENT OCCLUDED",
        [0xC01E0007] = "GRAPHICS PRESENT DENIED",
        [0xC01E0008] = "GRAPHICS CANNOTCOLORCONVERT",
        [0xC01E000B] = "GRAPHICS PRESENT REDIRECTION DISABLED",
        [0xC01E000C] = "GRAPHICS PRESENT UNOCCLUDED",
        [0xC01E0100] = "GRAPHICS NO VIDEO MEMORY",
        [0xC01E0101] = "GRAPHICS CANT LOCK MEMORY",
        [0xC01E0102] = "GRAPHICS ALLOCATION BUSY",
        [0xC01E0103] = "GRAPHICS TOO MANY REFERENCES",
        [0xC01E0104] = "GRAPHICS TRY AGAIN LATER",
        [0xC01E0105] = "GRAPHICS TRY AGAIN NOW",
        [0xC01E0106] = "GRAPHICS ALLOCATION INVALID",
        [0xC01E0107] = "GRAPHICS UNSWIZZLING APERTURE UNAVAILABLE",
        [0xC01E0108] = "GRAPHICS UNSWIZZLING APERTURE UNSUPPORTED",
        [0xC01E0109] = "GRAPHICS CANT EVICT PINNED ALLOCATION",
        [0xC01E0110] = "GRAPHICS INVALID ALLOCATION USAGE",
        [0xC01E0111] = "GRAPHICS CANT RENDER LOCKED ALLOCATION",
        [0xC01E0112] = "GRAPHICS ALLOCATION CLOSED",
        [0xC01E0113] = "GRAPHICS INVALID ALLOCATION INSTANCE",
        [0xC01E0114] = "GRAPHICS INVALID ALLOCATION HANDLE",
        [0xC01E0115] = "GRAPHICS WRONG ALLOCATION DEVICE",
        [0xC01E0116] = "GRAPHICS ALLOCATION CONTENT LOST",
        [0xC01E0200] = "GRAPHICS GPU EXCEPTION ON DEVICE",
        [0xC01E0300] = "GRAPHICS INVALID VIDPN TOPOLOGY",
        [0xC01E0301] = "GRAPHICS VIDPN TOPOLOGY NOT SUPPORTED",
        [0xC01E0302] = "GRAPHICS VIDPN TOPOLOGY CURRENTLY NOT SUPPORTED",
        [0xC01E0303] = "GRAPHICS INVALID VIDPN",
        [0xC01E0304] = "GRAPHICS INVALID VIDEO PRESENT SOURCE",
        [0xC01E0305] = "GRAPHICS INVALID VIDEO PRESENT TARGET",
        [0xC01E0306] = "GRAPHICS VIDPN MODALITY NOT SUPPORTED",
        [0xC01E0308] = "GRAPHICS INVALID VIDPN SOURCEMODESET",
        [0xC01E0309] = "GRAPHICS INVALID VIDPN TARGETMODESET",
        [0xC01E030A] = "GRAPHICS INVALID FREQUENCY",
        [0xC01E030B] = "GRAPHICS INVALID ACTIVE REGION",
        [0xC01E030C] = "GRAPHICS INVALID TOTAL REGION",
        [0xC01E0310] = "GRAPHICS INVALID VIDEO PRESENT SOURCE MODE",
        [0xC01E0311] = "GRAPHICS INVALID VIDEO PRESENT TARGET MODE",
        [0xC01E0312] = "GRAPHICS PINNED MODE MUST REMAIN IN SET",
        [0xC01E0313] = "GRAPHICS PATH ALREADY IN TOPOLOGY",
        [0xC01E0314] = "GRAPHICS MODE ALREADY IN MODESET",
        [0xC01E0315] = "GRAPHICS INVALID VIDEOPRESENTSOURCESET",
        [0xC01E0316] = "GRAPHICS INVALID VIDEOPRESENTTARGETSET",
        [0xC01E0317] = "GRAPHICS SOURCE ALREADY IN SET",
        [0xC01E0318] = "GRAPHICS TARGET ALREADY IN SET",
        [0xC01E0319] = "GRAPHICS INVALID VIDPN PRESENT PATH",
        [0xC01E031A] = "GRAPHICS NO RECOMMENDED VIDPN TOPOLOGY",
        [0xC01E031B] = "GRAPHICS INVALID MONITOR FREQUENCYRANGESET",
        [0xC01E031C] = "GRAPHICS INVALID MONITOR FREQUENCYRANGE",
        [0xC01E031D] = "GRAPHICS FREQUENCYRANGE NOT IN SET",
        [0xC01E031F] = "GRAPHICS FREQUENCYRANGE ALREADY IN SET",
        [0xC01E0320] = "GRAPHICS STALE MODESET",
        [0xC01E0321] = "GRAPHICS INVALID MONITOR SOURCEMODESET",
        [0xC01E0322] = "GRAPHICS INVALID MONITOR SOURCE MODE",
        [0xC01E0323] = "GRAPHICS NO RECOMMENDED FUNCTIONAL VIDPN",
        [0xC01E0324] = "GRAPHICS MODE ID MUST BE UNIQUE",
        [0xC01E0325] = "GRAPHICS EMPTY ADAPTER MONITOR MODE SUPPORT INTERSECTION",
        [0xC01E0326] = "GRAPHICS VIDEO PRESENT TARGETS LESS THAN SOURCES",
        [0xC01E0327] = "GRAPHICS PATH NOT IN TOPOLOGY",
        [0xC01E0328] = "GRAPHICS ADAPTER MUST HAVE AT LEAST ONE SOURCE",
        [0xC01E0329] = "GRAPHICS ADAPTER MUST HAVE AT LEAST ONE TARGET",
        [0xC01E032A] = "GRAPHICS INVALID MONITORDESCRIPTORSET",
        [0xC01E032B] = "GRAPHICS INVALID MONITORDESCRIPTOR",
        [0xC01E032C] = "GRAPHICS MONITORDESCRIPTOR NOT IN SET",
        [0xC01E032D] = "GRAPHICS MONITORDESCRIPTOR ALREADY IN SET",
        [0xC01E032E] = "GRAPHICS MONITORDESCRIPTOR ID MUST BE UNIQUE",
        [0xC01E032F] = "GRAPHICS INVALID VIDPN TARGET SUBSET TYPE",
        [0xC01E0330] = "GRAPHICS RESOURCES NOT RELATED",
        [0xC01E0331] = "GRAPHICS SOURCE ID MUST BE UNIQUE",
        [0xC01E0332] = "GRAPHICS TARGET ID MUST BE UNIQUE",
        [0xC01E0333] = "GRAPHICS NO AVAILABLE VIDPN TARGET",
        [0xC01E0334] = "GRAPHICS MONITOR COULD NOT BE ASSOCIATED WITH ADAPTER",
        [0xC01E0335] = "GRAPHICS NO VIDPNMGR",
        [0xC01E0336] = "GRAPHICS NO ACTIVE VIDPN",
        [0xC01E0337] = "GRAPHICS STALE VIDPN TOPOLOGY",
        [0xC01E0338] = "GRAPHICS MONITOR NOT CONNECTED",
        [0xC01E0339] = "GRAPHICS SOURCE NOT IN TOPOLOGY",
        [0xC01E033A] = "GRAPHICS INVALID PRIMARYSURFACE SIZE",
        [0xC01E033B] = "GRAPHICS INVALID VISIBLEREGION SIZE",
        [0xC01E033C] = "GRAPHICS INVALID STRIDE",
        [0xC01E033D] = "GRAPHICS INVALID PIXELFORMAT",
        [0xC01E033E] = "GRAPHICS INVALID COLORBASIS",
        [0xC01E033F] = "GRAPHICS INVALID PIXELVALUEACCESSMODE",
        [0xC01E0340] = "GRAPHICS TARGET NOT IN TOPOLOGY",
        [0xC01E0341] = "GRAPHICS NO DISPLAY MODE MANAGEMENT SUPPORT",
        [0xC01E0342] = "GRAPHICS VIDPN SOURCE IN USE",
        [0xC01E0343] = "GRAPHICS CANT ACCESS ACTIVE VIDPN",
        [0xC01E0344] = "GRAPHICS INVALID PATH IMPORTANCE ORDINAL",
        [0xC01E0345] = "GRAPHICS INVALID PATH CONTENT GEOMETRY TRANSFORMATION",
        [0xC01E0346] = "GRAPHICS PATH CONTENT GEOMETRY TRANSFORMATION NOT SUPPORTED",
        [0xC01E0347] = "GRAPHICS INVALID GAMMA RAMP",
        [0xC01E0348] = "GRAPHICS GAMMA RAMP NOT SUPPORTED",
        [0xC01E0349] = "GRAPHICS MULTISAMPLING NOT SUPPORTED",
        [0xC01E034A] = "GRAPHICS MODE NOT IN MODESET",
        [0xC01E034D] = "GRAPHICS INVALID VIDPN TOPOLOGY RECOMMENDATION REASON",
        [0xC01E034E] = "GRAPHICS INVALID PATH CONTENT TYPE",
        [0xC01E034F] = "GRAPHICS INVALID COPYPROTECTION TYPE",
        [0xC01E0350] = "GRAPHICS UNASSIGNED MODESET ALREADY EXISTS",
        [0xC01E0352] = "GRAPHICS INVALID SCANLINE ORDERING",
        [0xC01E0353] = "GRAPHICS TOPOLOGY CHANGES NOT ALLOWED",
        [0xC01E0354] = "GRAPHICS NO AVAILABLE IMPORTANCE ORDINALS",
        [0xC01E0355] = "GRAPHICS INCOMPATIBLE PRIVATE FORMAT",
        [0xC01E0356] = "GRAPHICS INVALID MODE PRUNING ALGORITHM",
        [0xC01E0357] = "GRAPHICS INVALID MONITOR CAPABILITY ORIGIN",
        [0xC01E0358] = "GRAPHICS INVALID MONITOR FREQUENCYRANGE CONSTRAINT",
        [0xC01E0359] = "GRAPHICS MAX NUM PATHS REACHED",
        [0xC01E035A] = "GRAPHICS CANCEL VIDPN TOPOLOGY AUGMENTATION",
        [0xC01E035B] = "GRAPHICS INVALID CLIENT TYPE",
        [0xC01E035C] = "GRAPHICS CLIENTVIDPN NOT SET",
        [0xC01E0400] = "GRAPHICS SPECIFIED CHILD ALREADY CONNECTED",
        [0xC01E0401] = "GRAPHICS CHILD DESCRIPTOR NOT SUPPORTED",
        [0xC01E0430] = "GRAPHICS NOT A LINKED ADAPTER",
        [0xC01E0431] = "GRAPHICS LEADLINK NOT ENUMERATED",
        [0xC01E0432] = "GRAPHICS CHAINLINKS NOT ENUMERATED",
        [0xC01E0433] = "GRAPHICS ADAPTER CHAIN NOT READY",
        [0xC01E0434] = "GRAPHICS CHAINLINKS NOT STARTED",
        [0xC01E0435] = "GRAPHICS CHAINLINKS NOT POWERED ON",
        [0xC01E0436] = "GRAPHICS INCONSISTENT DEVICE LINK STATE",
        [0xC01E0438] = "GRAPHICS NOT POST DEVICE DRIVER",
        [0xC01E043B] = "GRAPHICS ADAPTER ACCESS NOT EXCLUDED",
        [0xC01E0500] = "GRAPHICS OPM NOT SUPPORTED",
        [0xC01E0501] = "GRAPHICS COPP NOT SUPPORTED",
        [0xC01E0502] = "GRAPHICS UAB NOT SUPPORTED",
        [0xC01E0503] = "GRAPHICS OPM INVALID ENCRYPTED PARAMETERS",
        [0xC01E0504] = "GRAPHICS OPM PARAMETER ARRAY TOO SMALL",
        [0xC01E0505] = "GRAPHICS OPM NO PROTECTED OUTPUTS EXIST",
        [0xC01E0506] = "GRAPHICS PVP NO DISPLAY DEVICE CORRESPONDS TO NAME",
        [0xC01E0507] = "GRAPHICS PVP DISPLAY DEVICE NOT ATTACHED TO DESKTOP",
        [0xC01E0508] = "GRAPHICS PVP MIRRORING DEVICES NOT SUPPORTED",
        [0xC01E050A] = "GRAPHICS OPM INVALID POINTER",
        [0xC01E050B] = "GRAPHICS OPM INTERNAL ERROR",
        [0xC01E050C] = "GRAPHICS OPM INVALID HANDLE",
        [0xC01E050D] = "GRAPHICS PVP NO MONITORS CORRESPOND TO DISPLAY DEVICE",
        [0xC01E050E] = "GRAPHICS PVP INVALID CERTIFICATE LENGTH",
        [0xC01E050F] = "GRAPHICS OPM SPANNING MODE ENABLED",
        [0xC01E0510] = "GRAPHICS OPM THEATER MODE ENABLED",
        [0xC01E0511] = "GRAPHICS PVP HFS FAILED",
        [0xC01E0512] = "GRAPHICS OPM INVALID SRM",
        [0xC01E0513] = "GRAPHICS OPM OUTPUT DOES NOT SUPPORT HDCP",
        [0xC01E0514] = "GRAPHICS OPM OUTPUT DOES NOT SUPPORT ACP",
        [0xC01E0515] = "GRAPHICS OPM OUTPUT DOES NOT SUPPORT CGMSA",
        [0xC01E0516] = "GRAPHICS OPM HDCP SRM NEVER SET",
        [0xC01E0517] = "GRAPHICS OPM RESOLUTION TOO HIGH",
        [0xC01E0518] = "GRAPHICS OPM ALL HDCP HARDWARE ALREADY IN USE",
        [0xC01E051A] = "GRAPHICS OPM PROTECTED OUTPUT NO LONGER EXISTS",
        [0xC01E051B] = "GRAPHICS OPM SESSION TYPE CHANGE IN PROGRESS",
        [0xC01E051C] = "GRAPHICS OPM PROTECTED OUTPUT DOES NOT HAVE COPP SEMANTICS",
        [0xC01E051D] = "GRAPHICS OPM INVALID INFORMATION REQUEST",
        [0xC01E051E] = "GRAPHICS OPM DRIVER INTERNAL ERROR",
        [0xC01E051F] = "GRAPHICS OPM PROTECTED OUTPUT DOES NOT HAVE OPM SEMANTICS",
        [0xC01E0520] = "GRAPHICS OPM SIGNALING NOT SUPPORTED",
        [0xC01E0521] = "GRAPHICS OPM INVALID CONFIGURATION REQUEST",
        [0xC01E0580] = "GRAPHICS I2C NOT SUPPORTED",
        [0xC01E0581] = "GRAPHICS I2C DEVICE DOES NOT EXIST",
        [0xC01E0582] = "GRAPHICS I2C ERROR TRANSMITTING DATA",
        [0xC01E0583] = "GRAPHICS I2C ERROR RECEIVING DATA",
        [0xC01E0584] = "GRAPHICS DDCCI VCP NOT SUPPORTED",
        [0xC01E0585] = "GRAPHICS DDCCI INVALID DATA",
        [0xC01E0586] = "GRAPHICS DDCCI MONITOR RETURNED INVALID TIMING STATUS BYTE",
        [0xC01E0587] = "GRAPHICS DDCCI INVALID CAPABILITIES STRING",
        [0xC01E0588] = "GRAPHICS MCA INTERNAL ERROR",
        [0xC01E0589] = "GRAPHICS DDCCI INVALID MESSAGE COMMAND",
        [0xC01E058A] = "GRAPHICS DDCCI INVALID MESSAGE LENGTH",
        [0xC01E058B] = "GRAPHICS DDCCI INVALID MESSAGE CHECKSUM",
        [0xC01E058C] = "GRAPHICS INVALID PHYSICAL MONITOR HANDLE",
        [0xC01E058D] = "GRAPHICS MONITOR NO LONGER EXISTS",
        [0xC01E05E0] = "GRAPHICS ONLY CONSOLE SESSION SUPPORTED",
        [0xC01E05E1] = "GRAPHICS NO DISPLAY DEVICE CORRESPONDS TO NAME",
        [0xC01E05E2] = "GRAPHICS DISPLAY DEVICE NOT ATTACHED TO DESKTOP",
        [0xC01E05E3] = "GRAPHICS MIRRORING DEVICES NOT SUPPORTED",
        [0xC01E05E4] = "GRAPHICS INVALID POINTER",
        [0xC01E05E5] = "GRAPHICS NO MONITORS CORRESPOND TO DISPLAY DEVICE",
        [0xC01E05E6] = "GRAPHICS PARAMETER ARRAY TOO SMALL",
        [0xC01E05E7] = "GRAPHICS INTERNAL ERROR",
        [0xC01E05E8] = "GRAPHICS SESSION TYPE CHANGE IN PROGRESS",
        [0xC0210000] = "FVE LOCKED VOLUME",
        [0xC0210001] = "FVE NOT ENCRYPTED",
        [0xC0210002] = "FVE BAD INFORMATION",
        [0xC0210003] = "FVE TOO SMALL",
        [0xC0210004] = "FVE FAILED WRONG FS",
        [0xC0210005] = "FVE FAILED BAD FS",
        [0xC0210006] = "FVE FS NOT EXTENDED",
        [0xC0210007] = "FVE FS MOUNTED",
        [0xC0210008] = "FVE NO LICENSE",
        [0xC0210009] = "FVE ACTION NOT ALLOWED",
        [0xC021000A] = "FVE BAD DATA",
        [0xC021000B] = "FVE VOLUME NOT BOUND",
        [0xC021000C] = "FVE NOT DATA VOLUME",
        [0xC021000D] = "FVE CONV READ ERROR",
        [0xC021000E] = "FVE CONV WRITE ERROR",
        [0xC021000F] = "FVE OVERLAPPED UPDATE",
        [0xC0210010] = "FVE FAILED SECTOR SIZE",
        [0xC0210011] = "FVE FAILED AUTHENTICATION",
        [0xC0210012] = "FVE NOT OS VOLUME",
        [0xC0210013] = "FVE KEYFILE NOT FOUND",
        [0xC0210014] = "FVE KEYFILE INVALID",
        [0xC0210015] = "FVE KEYFILE NO VMK",
        [0xC0210016] = "FVE TPM DISABLED",
        [0xC0210017] = "FVE TPM SRK AUTH NOT ZERO",
        [0xC0210018] = "FVE TPM INVALID PCR",
        [0xC0210019] = "FVE TPM NO VMK",
        [0xC021001A] = "FVE PIN INVALID",
        [0xC021001B] = "FVE AUTH INVALID APPLICATION",
        [0xC021001C] = "FVE AUTH INVALID CONFIG",
        [0xC021001E] = "FVE DRY RUN FAILED",
        [0xC021001F] = "FVE BAD METADATA POINTER",
        [0xC0210020] = "FVE OLD METADATA COPY",
        [0xC0210021] = "FVE REBOOT REQUIRED",
        [0xC0210022] = "FVE RAW ACCESS",
        [0xC0210023] = "FVE RAW BLOCKED",
        [0xC0210026] = "FVE NO FEATURE LICENSE",
        [0xC0210027] = "FVE POLICY USER DISABLE RDV NOT ALLOWED",
        [0xC0210028] = "FVE CONV RECOVERY FAILED",
        [0xC0210029] = "FVE VIRTUALIZED SPACE TOO BIG",
        [0xC0210030] = "FVE VOLUME TOO SMALL",
        [0xC0220001] = "FWP CALLOUT NOT FOUND",
        [0xC0220002] = "FWP CONDITION NOT FOUND",
        [0xC0220003] = "FWP FILTER NOT FOUND",
        [0xC0220004] = "FWP LAYER NOT FOUND",
        [0xC0220005] = "FWP PROVIDER NOT FOUND",
        [0xC0220006] = "FWP PROVIDER CONTEXT NOT FOUND",
        [0xC0220007] = "FWP SUBLAYER NOT FOUND",
        [0xC0220008] = "FWP NOT FOUND",
        [0xC0220009] = "FWP ALREADY EXISTS",
        [0xC022000A] = "FWP IN USE",
        [0xC022000B] = "FWP DYNAMIC SESSION IN PROGRESS",
        [0xC022000C] = "FWP WRONG SESSION",
        [0xC022000D] = "FWP NO TXN IN PROGRESS",
        [0xC022000E] = "FWP TXN IN PROGRESS",
        [0xC022000F] = "FWP TXN ABORTED",
        [0xC0220010] = "FWP SESSION ABORTED",
        [0xC0220011] = "FWP INCOMPATIBLE TXN",
        [0xC0220012] = "FWP TIMEOUT",
        [0xC0220013] = "FWP NET EVENTS DISABLED",
        [0xC0220014] = "FWP INCOMPATIBLE LAYER",
        [0xC0220015] = "FWP KM CLIENTS ONLY",
        [0xC0220016] = "FWP LIFETIME MISMATCH",
        [0xC0220017] = "FWP BUILTIN OBJECT",
        [0xC0220018] = "FWP TOO MANY BOOTTIME FILTERS",
        [0xC0220018] = "FWP TOO MANY CALLOUTS",
        [0xC0220019] = "FWP NOTIFICATION DROPPED",
        [0xC022001A] = "FWP TRAFFIC MISMATCH",
        [0xC022001B] = "FWP INCOMPATIBLE SA STATE",
        [0xC022001C] = "FWP NULL POINTER",
        [0xC022001D] = "FWP INVALID ENUMERATOR",
        [0xC022001E] = "FWP INVALID FLAGS",
        [0xC022001F] = "FWP INVALID NET MASK",
        [0xC0220020] = "FWP INVALID RANGE",
        [0xC0220021] = "FWP INVALID INTERVAL",
        [0xC0220022] = "FWP ZERO LENGTH ARRAY",
        [0xC0220023] = "FWP NULL DISPLAY NAME",
        [0xC0220024] = "FWP INVALID ACTION TYPE",
        [0xC0220025] = "FWP INVALID WEIGHT",
        [0xC0220026] = "FWP MATCH TYPE MISMATCH",
        [0xC0220027] = "FWP TYPE MISMATCH",
        [0xC0220028] = "FWP OUT OF BOUNDS",
        [0xC0220029] = "FWP RESERVED",
        [0xC022002A] = "FWP DUPLICATE CONDITION",
        [0xC022002B] = "FWP DUPLICATE KEYMOD",
        [0xC022002C] = "FWP ACTION INCOMPATIBLE WITH LAYER",
        [0xC022002D] = "FWP ACTION INCOMPATIBLE WITH SUBLAYER",
        [0xC022002E] = "FWP CONTEXT INCOMPATIBLE WITH LAYER",
        [0xC022002F] = "FWP CONTEXT INCOMPATIBLE WITH CALLOUT",
        [0xC0220030] = "FWP INCOMPATIBLE AUTH METHOD",
        [0xC0220031] = "FWP INCOMPATIBLE DH GROUP",
        [0xC0220032] = "FWP EM NOT SUPPORTED",
        [0xC0220033] = "FWP NEVER MATCH",
        [0xC0220034] = "FWP PROVIDER CONTEXT MISMATCH",
        [0xC0220035] = "FWP INVALID PARAMETER",
        [0xC0220036] = "FWP TOO MANY SUBLAYERS",
        [0xC0220037] = "FWP CALLOUT NOTIFICATION FAILED",
        [0xC0220038] = "FWP INCOMPATIBLE AUTH CONFIG",
        [0xC0220039] = "FWP INCOMPATIBLE CIPHER CONFIG",
        [0xC022003C] = "FWP DUPLICATE AUTH METHOD",
        [0xC0220100] = "FWP TCPIP NOT READY",
        [0xC0220101] = "FWP INJECT HANDLE CLOSING",
        [0xC0220102] = "FWP INJECT HANDLE STALE",
        [0xC0220103] = "FWP CANNOT PEND",
        [0xC0230002] = "NDIS CLOSING",
        [0xC0230004] = "NDIS BAD VERSION",
        [0xC0230005] = "NDIS BAD CHARACTERISTICS",
        [0xC0230006] = "NDIS ADAPTER NOT FOUND",
        [0xC0230007] = "NDIS OPEN FAILED",
        [0xC0230008] = "NDIS DEVICE FAILED",
        [0xC0230009] = "NDIS MULTICAST FULL",
        [0xC023000A] = "NDIS MULTICAST EXISTS",
        [0xC023000B] = "NDIS MULTICAST NOT FOUND",
        [0xC023000C] = "NDIS REQUEST ABORTED",
        [0xC023000D] = "NDIS RESET IN PROGRESS",
        [0xC023000F] = "NDIS INVALID PACKET",
        [0xC0230010] = "NDIS INVALID DEVICE REQUEST",
        [0xC0230011] = "NDIS ADAPTER NOT READY",
        [0xC0230014] = "NDIS INVALID LENGTH",
        [0xC0230015] = "NDIS INVALID DATA",
        [0xC0230016] = "NDIS BUFFER TOO SHORT",
        [0xC0230017] = "NDIS INVALID OID",
        [0xC0230018] = "NDIS ADAPTER REMOVED",
        [0xC0230019] = "NDIS UNSUPPORTED MEDIA",
        [0xC023001A] = "NDIS GROUP ADDRESS IN USE",
        [0xC023001B] = "NDIS FILE NOT FOUND",
        [0xC023001C] = "NDIS ERROR READING FILE",
        [0xC023001D] = "NDIS ALREADY MAPPED",
        [0xC023001E] = "NDIS RESOURCE CONFLICT",
        [0xC023001F] = "NDIS MEDIA DISCONNECTED",
        [0xC0230022] = "NDIS INVALID ADDRESS",
        [0xC023002A] = "NDIS PAUSED",
        [0xC023002B] = "NDIS INTERFACE NOT FOUND",
        [0xC023002C] = "NDIS UNSUPPORTED REVISION",
        [0xC023002D] = "NDIS INVALID PORT",
        [0xC023002E] = "NDIS INVALID PORT STATE",
        [0xC023002F] = "NDIS LOW POWER STATE",
        [0xC02300BB] = "NDIS NOT SUPPORTED",
        [0xC023100F] = "NDIS OFFLOAD POLICY",
        [0xC0231012] = "NDIS OFFLOAD CONNECTION REJECTED",
        [0xC0231013] = "NDIS OFFLOAD PATH REJECTED",
        [0xC0232000] = "NDIS DOT11 AUTO CONFIG ENABLED",
        [0xC0232001] = "NDIS DOT11 MEDIA IN USE",
        [0xC0232002] = "NDIS DOT11 POWER STATE INVALID",
        [0xC0232003] = "NDIS PM WOL PATTERN LIST FULL",
        [0xC0232004] = "NDIS PM PROTOCOL OFFLOAD LIST FULL",
        [0xC0360001] = "IPSEC BAD SPI",
        [0xC0360002] = "IPSEC SA LIFETIME EXPIRED",
        [0xC0360003] = "IPSEC WRONG SA",
        [0xC0360004] = "IPSEC REPLAY CHECK FAILED",
        [0xC0360005] = "IPSEC INVALID PACKET",
        [0xC0360006] = "IPSEC INTEGRITY CHECK FAILED",
        [0xC0360007] = "IPSEC CLEAR TEXT DROP",
        [0xC0360008] = "IPSEC AUTH FIREWALL DROP",
        [0xC0360009] = "IPSEC THROTTLE DROP",
        [0xC0368000] = "IPSEC DOSP BLOCK",
        [0xC0368001] = "IPSEC DOSP RECEIVED MULTICAST",
        [0xC0368002] = "IPSEC DOSP INVALID PACKET",
        [0xC0368003] = "IPSEC DOSP STATE LOOKUP FAILED",
        [0xC0368004] = "IPSEC DOSP MAX ENTRIES",
        [0xC0368005] = "IPSEC DOSP KEYMOD NOT ALLOWED",
        [0xC0368006] = "IPSEC DOSP MAX PER IP RATELIMIT QUEUES",
        [0xC038005B] = "VOLMGR MIRROR NOT SUPPORTED",
        [0xC038005C] = "VOLMGR RAID5 NOT SUPPORTED",
        [0xC03A0014] = "VIRTDISK PROVIDER NOT FOUND",
        [0xC03A0015] = "VIRTDISK NOT VIRTUAL DISK",
        [0xC03A0016] = "VHD PARENT VHD ACCESS DENIED",
        [0xC03A0017] = "VHD CHILD PARENT SIZE MISMATCH",
        [0xC03A0018] = "VHD DIFFERENCING CHAIN CYCLE DETECTED",
        [0xC03A0019] = "VHD DIFFERENCING CHAIN ERROR IN PARENT",
    })
end

--[[               ----------------
                   CONVERT SNMP OID
                   ----------------

2016.08.15.1  wm  local scope oidSub
2016.05.20.1  wm  don't define OIDTable every time called
2016.05.12.1  wm  bugfix: lostDot -> lastDot
2013.08.22.1  wm  Moved from nwsnmp.lua

Convert an SNMP OID from numeric to "human readable" format.

Expects a lua string of the numeric OID.

Returns a lua string of the human-readable OID.  Any unknown
portion of the OID remains numeric.

--]]

local OIDTable = ({
                ["1.3"] = "org",
                ["1.3.6"] = "dod",
                ["1.3.6.1"] = "internet",
                ["1.3.6.1.1"] = "directory",
                ["1.3.6.1.2"] = "mgmt",
                ["1.3.6.1.2.1"] = "mib-2",
                ["1.3.6.1.2.1.1"] = "system",
                ["1.3.6.1.2.1.1.1"] = "sysDescr",
                ["1.3.6.1.2.1.1.2"] = "sysObjectID",
                ["1.3.6.1.2.1.1.3"] = "sysUpTime",
                ["1.3.6.1.2.1.1.3.0"] = "sysUpTimeInstance",
                ["1.3.6.1.2.1.1.4"] = "sysContact",
                ["1.3.6.1.2.1.1.5"] = "sysName",
                ["1.3.6.1.2.1.1.6"] = "sysLocation",
                ["1.3.6.1.2.1.1.7"] = "sysServices",
                ["1.3.6.1.2.1.1.8"] = "sysORLastChange",
                ["1.3.6.1.2.1.1.9"] = "sysORTable",
                ["1.3.6.1.2.1.1.9.1"] = "sysOREntry",
                ["1.3.6.1.2.1.1.9.1.1"] = "sysORIndex",
                ["1.3.6.1.2.1.1.9.1.2"] = "sysORID",
                ["1.3.6.1.2.1.1.9.1.3"] = "sysORDescr",
                ["1.3.6.1.2.1.1.9.1.4"] = "sysORUpTime",
                ["1.3.6.1.2.1.2"] = "interfaces",
                ["1.3.6.1.2.1.2.1"] = "ifNumber",
                ["1.3.6.1.2.1.2.2"] = "ifTable",
                ["1.3.6.1.2.1.2.2.1"] = "ifEntry",
                ["1.3.6.1.2.1.2.2.1.1"] = "ifIndex",
                ["1.3.6.1.2.1.2.2.1.2"] = "ifDescr",
                ["1.3.6.1.2.1.2.2.1.3"] = "ifType",
                ["1.3.6.1.2.1.2.2.1.4"] = "ifMtu",
                ["1.3.6.1.2.1.2.2.1.5"] = "ifSpeed",
                ["1.3.6.1.2.1.2.2.1.6"] = "ifPhysAddress",
                ["1.3.6.1.2.1.2.2.1.7"] = "ifAdminStatus",
                ["1.3.6.1.2.1.2.2.1.8"] = "ifOperStatus",
                ["1.3.6.1.2.1.2.2.1.9"] = "ifLastChange",
                ["1.3.6.1.2.1.2.2.1.10"] = "ifInOctets",
                ["1.3.6.1.2.1.2.2.1.11"] = "ifInUcastPkts",
                ["1.3.6.1.2.1.2.2.1.12"] = "ifInNUcastPkts",
                ["1.3.6.1.2.1.2.2.1.13"] = "ifInDiscards",
                ["1.3.6.1.2.1.2.2.1.14"] = "ifInErrors",
                ["1.3.6.1.2.1.2.2.1.15"] = "ifInUnknownProtos",
                ["1.3.6.1.2.1.2.2.1.16"] = "ifOutOctets",
                ["1.3.6.1.2.1.2.2.1.17"] = "ifOutUcastPkts",
                ["1.3.6.1.2.1.2.2.1.18"] = "ifOutNUcastPkts",
                ["1.3.6.1.2.1.2.2.1.19"] = "ifOutDiscards",
                ["1.3.6.1.2.1.2.2.1.20"] = "ifOutErrors",
                ["1.3.6.1.2.1.2.2.1.21"] = "ifOutQLen",
                ["1.3.6.1.2.1.2.2.1.22"] = "ifSpecific",
                ["1.3.6.1.2.1.3"] = "at",
                ["1.3.6.1.2.1.3.1"] = "atTable",
                ["1.3.6.1.2.1.3.1.1"] = "atEntry",
                ["1.3.6.1.2.1.3.1.1.1"] = "atIfIndex",
                ["1.3.6.1.2.1.3.1.1.2"] = "atPhysAddress",
                ["1.3.6.1.2.1.3.1.1.3"] = "atNetAddress",
                ["1.3.6.1.2.1.4"] = "ip",
                ["1.3.6.1.2.1.4.1"] = "ipForwarding",
                ["1.3.6.1.2.1.4.2"] = "ipDefaultTTL",
                ["1.3.6.1.2.1.4.3"] = "ipInReceives",
                ["1.3.6.1.2.1.4.4"] = "ipInHdrErrors",
                ["1.3.6.1.2.1.4.5"] = "ipInAddrErrors",
                ["1.3.6.1.2.1.4.6"] = "ipForwDatagrams",
                ["1.3.6.1.2.1.4.7"] = "ipInUnknownProtos",
                ["1.3.6.1.2.1.4.8"] = "ipInDiscards",
                ["1.3.6.1.2.1.4.9"] = "ipInDelivers",
                ["1.3.6.1.2.1.4.10"] = "ipOutRequests",
                ["1.3.6.1.2.1.4.11"] = "ipOutDiscards",
                ["1.3.6.1.2.1.4.12"] = "ipOutNoRoutes",
                ["1.3.6.1.2.1.4.13"] = "ipReasmTimeout",
                ["1.3.6.1.2.1.4.14"] = "ipReasmReqds",
                ["1.3.6.1.2.1.4.15"] = "ipReasmOKs",
                ["1.3.6.1.2.1.4.16"] = "ipReasmFails",
                ["1.3.6.1.2.1.4.17"] = "ipFragOKs",
                ["1.3.6.1.2.1.4.18"] = "ipFragFails",
                ["1.3.6.1.2.1.4.19"] = "ipFragCreates",
                ["1.3.6.1.2.1.4.20"] = "ipAddrTable",
                ["1.3.6.1.2.1.4.20.1"] = "ipAddrEntry",
                ["1.3.6.1.2.1.4.20.1.1"] = "ipAdEntAddr",
                ["1.3.6.1.2.1.4.20.1.2"] = "ipAdEntIfIndex",
                ["1.3.6.1.2.1.4.20.1.3"] = "ipAdEntNetMask",
                ["1.3.6.1.2.1.4.20.1.4"] = "ipAdEntBcastAddr",
                ["1.3.6.1.2.1.4.20.1.5"] = "ipAdEntReasmMaxSize",
                ["1.3.6.1.2.1.4.21"] = "ipRouteTable",
                ["1.3.6.1.2.1.4.21.1"] = "ipRouteEntry",
                ["1.3.6.1.2.1.4.21.1.1"] = "ipRouteDest",
                ["1.3.6.1.2.1.4.21.1.2"] = "ipRouteIfIndex",
                ["1.3.6.1.2.1.4.21.1.3"] = "ipRouteMetric1",
                ["1.3.6.1.2.1.4.21.1.4"] = "ipRouteMetric2",
                ["1.3.6.1.2.1.4.21.1.5"] = "ipRouteMetric3",
                ["1.3.6.1.2.1.4.21.1.6"] = "ipRouteMetric4",
                ["1.3.6.1.2.1.4.21.1.7"] = "ipRouteNextHop",
                ["1.3.6.1.2.1.4.21.1.8"] = "ipRouteType",
                ["1.3.6.1.2.1.4.21.1.9"] = "ipRouteProto",
                ["1.3.6.1.2.1.4.21.1.10"] = "ipRouteAge",
                ["1.3.6.1.2.1.4.21.1.11"] = "ipRouteMask",
                ["1.3.6.1.2.1.4.21.1.12"] = "ipRouteMetric5",
                ["1.3.6.1.2.1.4.21.1.13"] = "ipRouteInfo",
                ["1.3.6.1.2.1.4.22"] = "ipNetToMediaTable",
                ["1.3.6.1.2.1.4.22.1"] = "ipNetToMediaEntry",
                ["1.3.6.1.2.1.4.22.1.1"] = "ipNetToMediaIfIndex",
                ["1.3.6.1.2.1.4.22.1.2"] = "ipNetToMediaPhysAddress",
                ["1.3.6.1.2.1.4.22.1.3"] = "ipNetToMediaNetAddress",
                ["1.3.6.1.2.1.4.22.1.4"] = "ipNetToMediaType",
                ["1.3.6.1.2.1.4.23"] = "ipRoutingDiscards",
                ["1.3.6.1.2.1.4.25"] = "ipv6IpForwarding",
                ["1.3.6.1.2.1.4.26"] = "ipv6IpDefaultHopLimit",
                ["1.3.6.1.2.1.4.27"] = "ipv4InterfaceTableLastChange",
                ["1.3.6.1.2.1.4.28"] = "ipv4InterfaceTable",
                ["1.3.6.1.2.1.4.28.1"] = "ipv4InterfaceEntry",
                ["1.3.6.1.2.1.4.28.1.1"] = "ipv4InterfaceIfIndex",
                ["1.3.6.1.2.1.4.28.1.2"] = "ipv4InterfaceReasmMaxSize",
                ["1.3.6.1.2.1.4.28.1.3"] = "ipv4InterfaceEnableStatus",
                ["1.3.6.1.2.1.4.28.1.4"] = "ipv4InterfaceRetransmitTime",
                ["1.3.6.1.2.1.4.29"] = "ipv6InterfaceTableLastChange",
                ["1.3.6.1.2.1.4.30"] = "ipv6InterfaceTable",
                ["1.3.6.1.2.1.4.30.1"] = "ipv6InterfaceEntry",
                ["1.3.6.1.2.1.4.30.1.1"] = "ipv6InterfaceIfIndex",
                ["1.3.6.1.2.1.4.30.1.2"] = "ipv6InterfaceReasmMaxSize",
                ["1.3.6.1.2.1.4.30.1.3"] = "ipv6InterfaceIdentifier",
                ["1.3.6.1.2.1.4.30.1.5"] = "ipv6InterfaceEnableStatus",
                ["1.3.6.1.2.1.4.30.1.6"] = "ipv6InterfaceReachableTime",
                ["1.3.6.1.2.1.4.30.1.7"] = "ipv6InterfaceRetransmitTime",
                ["1.3.6.1.2.1.4.30.1.8"] = "ipv6InterfaceForwarding",
                ["1.3.6.1.2.1.4.31"] = "ipTrafficStats",
                ["1.3.6.1.2.1.4.31.1"] = "ipSystemStatsTable",
                ["1.3.6.1.2.1.4.31.1.1"] = "ipSystemStatsEntry",
                ["1.3.6.1.2.1.4.31.1.1.1"] = "ipSystemStatsIPVersion",
                ["1.3.6.1.2.1.4.31.1.1.3"] = "ipSystemStatsInReceives",
                ["1.3.6.1.2.1.4.31.1.1.4"] = "ipSystemStatsHCInReceives",
                ["1.3.6.1.2.1.4.31.1.1.5"] = "ipSystemStatsInOctets",
                ["1.3.6.1.2.1.4.31.1.1.6"] = "ipSystemStatsHCInOctets",
                ["1.3.6.1.2.1.4.31.1.1.7"] = "ipSystemStatsInHdrErrors",
                ["1.3.6.1.2.1.4.31.1.1.8"] = "ipSystemStatsInNoRoutes",
                ["1.3.6.1.2.1.4.31.1.1.9"] = "ipSystemStatsInAddrErrors",
                ["1.3.6.1.2.1.4.31.1.1.10"] = "ipSystemStatsInUnknownProtos",
                ["1.3.6.1.2.1.4.31.1.1.11"] = "ipSystemStatsInTruncatedPkts",
                ["1.3.6.1.2.1.4.31.1.1.12"] = "ipSystemStatsInForwDatagrams",
                ["1.3.6.1.2.1.4.31.1.1.13"] = "ipSystemStatsHCInForwDatagrams",
                ["1.3.6.1.2.1.4.31.1.1.14"] = "ipSystemStatsReasmReqds",
                ["1.3.6.1.2.1.4.31.1.1.15"] = "ipSystemStatsReasmOKs",
                ["1.3.6.1.2.1.4.31.1.1.16"] = "ipSystemStatsReasmFails",
                ["1.3.6.1.2.1.4.31.1.1.17"] = "ipSystemStatsInDiscards",
                ["1.3.6.1.2.1.4.31.1.1.18"] = "ipSystemStatsInDelivers",
                ["1.3.6.1.2.1.4.31.1.1.19"] = "ipSystemStatsHCInDelivers",
                ["1.3.6.1.2.1.4.31.1.1.20"] = "ipSystemStatsOutRequests",
                ["1.3.6.1.2.1.4.31.1.1.21"] = "ipSystemStatsHCOutRequests",
                ["1.3.6.1.2.1.4.31.1.1.22"] = "ipSystemStatsOutNoRoutes",
                ["1.3.6.1.2.1.4.31.1.1.23"] = "ipSystemStatsOutForwDatagrams",
                ["1.3.6.1.2.1.4.31.1.1.24"] = "ipSystemStatsHCOutForwDatagrams",
                ["1.3.6.1.2.1.4.31.1.1.25"] = "ipSystemStatsOutDiscards",
                ["1.3.6.1.2.1.4.31.1.1.26"] = "ipSystemStatsOutFragReqds",
                ["1.3.6.1.2.1.4.31.1.1.27"] = "ipSystemStatsOutFragOKs",
                ["1.3.6.1.2.1.4.31.1.1.28"] = "ipSystemStatsOutFragFails",
                ["1.3.6.1.2.1.4.31.1.1.29"] = "ipSystemStatsOutFragCreates",
                ["1.3.6.1.2.1.4.31.1.1.30"] = "ipSystemStatsOutTransmits",
                ["1.3.6.1.2.1.4.31.1.1.31"] = "ipSystemStatsHCOutTransmits",
                ["1.3.6.1.2.1.4.31.1.1.32"] = "ipSystemStatsOutOctets",
                ["1.3.6.1.2.1.4.31.1.1.33"] = "ipSystemStatsHCOutOctets",
                ["1.3.6.1.2.1.4.31.1.1.34"] = "ipSystemStatsInMcastPkts",
                ["1.3.6.1.2.1.4.31.1.1.35"] = "ipSystemStatsHCInMcastPkts",
                ["1.3.6.1.2.1.4.31.1.1.36"] = "ipSystemStatsInMcastOctets",
                ["1.3.6.1.2.1.4.31.1.1.37"] = "ipSystemStatsHCInMcastOctets",
                ["1.3.6.1.2.1.4.31.1.1.38"] = "ipSystemStatsOutMcastPkts",
                ["1.3.6.1.2.1.4.31.1.1.39"] = "ipSystemStatsHCOutMcastPkts",
                ["1.3.6.1.2.1.4.31.1.1.40"] = "ipSystemStatsOutMcastOctets",
                ["1.3.6.1.2.1.4.31.1.1.41"] = "ipSystemStatsHCOutMcastOctets",
                ["1.3.6.1.2.1.4.31.1.1.42"] = "ipSystemStatsInBcastPkts",
                ["1.3.6.1.2.1.4.31.1.1.43"] = "ipSystemStatsHCInBcastPkts",
                ["1.3.6.1.2.1.4.31.1.1.44"] = "ipSystemStatsOutBcastPkts",
                ["1.3.6.1.2.1.4.31.1.1.45"] = "ipSystemStatsHCOutBcastPkts",
                ["1.3.6.1.2.1.4.31.1.1.46"] = "ipSystemStatsDiscontinuityTime",
                ["1.3.6.1.2.1.4.31.1.1.47"] = "ipSystemStatsRefreshRate",
                ["1.3.6.1.2.1.4.31.2"] = "ipIfStatsTableLastChange",
                ["1.3.6.1.2.1.4.31.3"] = "ipIfStatsTable",
                ["1.3.6.1.2.1.4.31.3.1"] = "ipIfStatsEntry",
                ["1.3.6.1.2.1.4.31.3.1.1"] = "ipIfStatsIPVersion",
                ["1.3.6.1.2.1.4.31.3.1.2"] = "ipIfStatsIfIndex",
                ["1.3.6.1.2.1.4.31.3.1.3"] = "ipIfStatsInReceives",
                ["1.3.6.1.2.1.4.31.3.1.4"] = "ipIfStatsHCInReceives",
                ["1.3.6.1.2.1.4.31.3.1.5"] = "ipIfStatsInOctets",
                ["1.3.6.1.2.1.4.31.3.1.6"] = "ipIfStatsHCInOctets",
                ["1.3.6.1.2.1.4.31.3.1.7"] = "ipIfStatsInHdrErrors",
                ["1.3.6.1.2.1.4.31.3.1.8"] = "ipIfStatsInNoRoutes",
                ["1.3.6.1.2.1.4.31.3.1.9"] = "ipIfStatsInAddrErrors",
                ["1.3.6.1.2.1.4.31.3.1.10"] = "ipIfStatsInUnknownProtos",
                ["1.3.6.1.2.1.4.31.3.1.11"] = "ipIfStatsInTruncatedPkts",
                ["1.3.6.1.2.1.4.31.3.1.12"] = "ipIfStatsInForwDatagrams",
                ["1.3.6.1.2.1.4.31.3.1.13"] = "ipIfStatsHCInForwDatagrams",
                ["1.3.6.1.2.1.4.31.3.1.14"] = "ipIfStatsReasmReqds",
                ["1.3.6.1.2.1.4.31.3.1.15"] = "ipIfStatsReasmOKs",
                ["1.3.6.1.2.1.4.31.3.1.16"] = "ipIfStatsReasmFails",
                ["1.3.6.1.2.1.4.31.3.1.17"] = "ipIfStatsInDiscards",
                ["1.3.6.1.2.1.4.31.3.1.18"] = "ipIfStatsInDelivers",
                ["1.3.6.1.2.1.4.31.3.1.19"] = "ipIfStatsHCInDelivers",
                ["1.3.6.1.2.1.4.31.3.1.20"] = "ipIfStatsOutRequests",
                ["1.3.6.1.2.1.4.31.3.1.21"] = "ipIfStatsHCOutRequests",
                ["1.3.6.1.2.1.4.31.3.1.23"] = "ipIfStatsOutForwDatagrams",
                ["1.3.6.1.2.1.4.31.3.1.24"] = "ipIfStatsHCOutForwDatagrams",
                ["1.3.6.1.2.1.4.31.3.1.25"] = "ipIfStatsOutDiscards",
                ["1.3.6.1.2.1.4.31.3.1.26"] = "ipIfStatsOutFragReqds",
                ["1.3.6.1.2.1.4.31.3.1.27"] = "ipIfStatsOutFragOKs",
                ["1.3.6.1.2.1.4.31.3.1.28"] = "ipIfStatsOutFragFails",
                ["1.3.6.1.2.1.4.31.3.1.29"] = "ipIfStatsOutFragCreates",
                ["1.3.6.1.2.1.4.31.3.1.30"] = "ipIfStatsOutTransmits",
                ["1.3.6.1.2.1.4.31.3.1.31"] = "ipIfStatsHCOutTransmits",
                ["1.3.6.1.2.1.4.31.3.1.32"] = "ipIfStatsOutOctets",
                ["1.3.6.1.2.1.4.31.3.1.33"] = "ipIfStatsHCOutOctets",
                ["1.3.6.1.2.1.4.31.3.1.34"] = "ipIfStatsInMcastPkts",
                ["1.3.6.1.2.1.4.31.3.1.35"] = "ipIfStatsHCInMcastPkts",
                ["1.3.6.1.2.1.4.31.3.1.36"] = "ipIfStatsInMcastOctets",
                ["1.3.6.1.2.1.4.31.3.1.37"] = "ipIfStatsHCInMcastOctets",
                ["1.3.6.1.2.1.4.31.3.1.38"] = "ipIfStatsOutMcastPkts",
                ["1.3.6.1.2.1.4.31.3.1.39"] = "ipIfStatsHCOutMcastPkts",
                ["1.3.6.1.2.1.4.31.3.1.40"] = "ipIfStatsOutMcastOctets",
                ["1.3.6.1.2.1.4.31.3.1.41"] = "ipIfStatsHCOutMcastOctets",
                ["1.3.6.1.2.1.4.31.3.1.42"] = "ipIfStatsInBcastPkts",
                ["1.3.6.1.2.1.4.31.3.1.43"] = "ipIfStatsHCInBcastPkts",
                ["1.3.6.1.2.1.4.31.3.1.44"] = "ipIfStatsOutBcastPkts",
                ["1.3.6.1.2.1.4.31.3.1.45"] = "ipIfStatsHCOutBcastPkts",
                ["1.3.6.1.2.1.4.31.3.1.46"] = "ipIfStatsDiscontinuityTime",
                ["1.3.6.1.2.1.4.31.3.1.47"] = "ipIfStatsRefreshRate",
                ["1.3.6.1.2.1.4.32"] = "ipAddressPrefixTable",
                ["1.3.6.1.2.1.4.32.1"] = "ipAddressPrefixEntry",
                ["1.3.6.1.2.1.4.32.1.1"] = "ipAddressPrefixIfIndex",
                ["1.3.6.1.2.1.4.32.1.2"] = "ipAddressPrefixType",
                ["1.3.6.1.2.1.4.32.1.3"] = "ipAddressPrefixPrefix",
                ["1.3.6.1.2.1.4.32.1.4"] = "ipAddressPrefixLength",
                ["1.3.6.1.2.1.4.32.1.5"] = "ipAddressPrefixOrigin",
                ["1.3.6.1.2.1.4.32.1.6"] = "ipAddressPrefixOnLinkFlag",
                ["1.3.6.1.2.1.4.32.1.7"] = "ipAddressPrefixAutonomousFlag",
                ["1.3.6.1.2.1.4.32.1.8"] = "ipAddressPrefixAdvPreferredLifetime",
                ["1.3.6.1.2.1.4.32.1.9"] = "ipAddressPrefixAdvValidLifetime",
                ["1.3.6.1.2.1.4.33"] = "ipAddressSpinLock",
                ["1.3.6.1.2.1.4.34"] = "ipAddressTable",
                ["1.3.6.1.2.1.4.34.1"] = "ipAddressEntry",
                ["1.3.6.1.2.1.4.34.1.1"] = "ipAddressAddrType",
                ["1.3.6.1.2.1.4.34.1.2"] = "ipAddressAddr",
                ["1.3.6.1.2.1.4.34.1.3"] = "ipAddressIfIndex",
                ["1.3.6.1.2.1.4.34.1.4"] = "ipAddressType",
                ["1.3.6.1.2.1.4.34.1.5"] = "ipAddressPrefix",
                ["1.3.6.1.2.1.4.34.1.6"] = "ipAddressOrigin",
                ["1.3.6.1.2.1.4.34.1.7"] = "ipAddressStatus",
                ["1.3.6.1.2.1.4.34.1.8"] = "ipAddressCreated",
                ["1.3.6.1.2.1.4.34.1.9"] = "ipAddressLastChanged",
                ["1.3.6.1.2.1.4.34.1.10"] = "ipAddressRowStatus",
                ["1.3.6.1.2.1.4.34.1.11"] = "ipAddressStorageType",
                ["1.3.6.1.2.1.4.35"] = "ipNetToPhysicalTable",
                ["1.3.6.1.2.1.4.35.1"] = "ipNetToPhysicalEntry",
                ["1.3.6.1.2.1.4.35.1.1"] = "ipNetToPhysicalIfIndex",
                ["1.3.6.1.2.1.4.35.1.2"] = "ipNetToPhysicalNetAddressType",
                ["1.3.6.1.2.1.4.35.1.3"] = "ipNetToPhysicalNetAddress",
                ["1.3.6.1.2.1.4.35.1.4"] = "ipNetToPhysicalPhysAddress",
                ["1.3.6.1.2.1.4.35.1.5"] = "ipNetToPhysicalLastUpdated",
                ["1.3.6.1.2.1.4.35.1.6"] = "ipNetToPhysicalType",
                ["1.3.6.1.2.1.4.35.1.7"] = "ipNetToPhysicalState",
                ["1.3.6.1.2.1.4.35.1.8"] = "ipNetToPhysicalRowStatus",
                ["1.3.6.1.2.1.4.36"] = "ipv6ScopeZoneIndexTable",
                ["1.3.6.1.2.1.4.36.1"] = "ipv6ScopeZoneIndexEntry",
                ["1.3.6.1.2.1.4.36.1.1"] = "ipv6ScopeZoneIndexIfIndex",
                ["1.3.6.1.2.1.4.36.1.2"] = "ipv6ScopeZoneIndexLinkLocal",
                ["1.3.6.1.2.1.4.36.1.3"] = "ipv6ScopeZoneIndex3",
                ["1.3.6.1.2.1.4.36.1.4"] = "ipv6ScopeZoneIndexAdminLocal",
                ["1.3.6.1.2.1.4.36.1.5"] = "ipv6ScopeZoneIndexSiteLocal",
                ["1.3.6.1.2.1.4.36.1.6"] = "ipv6ScopeZoneIndex6",
                ["1.3.6.1.2.1.4.36.1.7"] = "ipv6ScopeZoneIndex7",
                ["1.3.6.1.2.1.4.36.1.8"] = "ipv6ScopeZoneIndexOrganizationLocal",
                ["1.3.6.1.2.1.4.36.1.9"] = "ipv6ScopeZoneIndex9",
                ["1.3.6.1.2.1.4.36.1.10"] = "ipv6ScopeZoneIndexA",
                ["1.3.6.1.2.1.4.36.1.11"] = "ipv6ScopeZoneIndexB",
                ["1.3.6.1.2.1.4.36.1.12"] = "ipv6ScopeZoneIndexC",
                ["1.3.6.1.2.1.4.36.1.13"] = "ipv6ScopeZoneIndexD",
                ["1.3.6.1.2.1.4.37"] = "ipDefaultRouterTable",
                ["1.3.6.1.2.1.4.37.1"] = "ipDefaultRouterEntry",
                ["1.3.6.1.2.1.4.37.1.1"] = "ipDefaultRouterAddressType",
                ["1.3.6.1.2.1.4.37.1.2"] = "ipDefaultRouterAddress",
                ["1.3.6.1.2.1.4.37.1.3"] = "ipDefaultRouterIfIndex",
                ["1.3.6.1.2.1.4.37.1.4"] = "ipDefaultRouterLifetime",
                ["1.3.6.1.2.1.4.37.1.5"] = "ipDefaultRouterPreference",
                ["1.3.6.1.2.1.4.38"] = "ipv6RouterAdvertSpinLock",
                ["1.3.6.1.2.1.4.39"] = "ipv6RouterAdvertTable",
                ["1.3.6.1.2.1.4.39.1"] = "ipv6RouterAdvertEntry",
                ["1.3.6.1.2.1.4.39.1.1"] = "ipv6RouterAdvertIfIndex",
                ["1.3.6.1.2.1.4.39.1.2"] = "ipv6RouterAdvertSendAdverts",
                ["1.3.6.1.2.1.4.39.1.3"] = "ipv6RouterAdvertMaxInterval",
                ["1.3.6.1.2.1.4.39.1.4"] = "ipv6RouterAdvertMinInterval",
                ["1.3.6.1.2.1.4.39.1.5"] = "ipv6RouterAdvertManagedFlag",
                ["1.3.6.1.2.1.4.39.1.6"] = "ipv6RouterAdvertOtherConfigFlag",
                ["1.3.6.1.2.1.4.39.1.7"] = "ipv6RouterAdvertLinkMTU",
                ["1.3.6.1.2.1.4.39.1.8"] = "ipv6RouterAdvertReachableTime",
                ["1.3.6.1.2.1.4.39.1.9"] = "ipv6RouterAdvertRetransmitTime",
                ["1.3.6.1.2.1.4.39.1.10"] = "ipv6RouterAdvertCurHopLimit",
                ["1.3.6.1.2.1.4.39.1.11"] = "ipv6RouterAdvertDefaultLifetime",
                ["1.3.6.1.2.1.4.39.1.12"] = "ipv6RouterAdvertRowStatus",
                ["1.3.6.1.2.1.5"] = "icmp",
                ["1.3.6.1.2.1.5.1"] = "icmpInMsgs",
                ["1.3.6.1.2.1.5.2"] = "icmpInErrors",
                ["1.3.6.1.2.1.5.3"] = "icmpInDestUnreachs",
                ["1.3.6.1.2.1.5.4"] = "icmpInTimeExcds",
                ["1.3.6.1.2.1.5.5"] = "icmpInParmProbs",
                ["1.3.6.1.2.1.5.6"] = "icmpInSrcQuenchs",
                ["1.3.6.1.2.1.5.7"] = "icmpInRedirects",
                ["1.3.6.1.2.1.5.8"] = "icmpInEchos",
                ["1.3.6.1.2.1.5.9"] = "icmpInEchoReps",
                ["1.3.6.1.2.1.5.10"] = "icmpInTimestamps",
                ["1.3.6.1.2.1.5.11"] = "icmpInTimestampReps",
                ["1.3.6.1.2.1.5.12"] = "icmpInAddrMasks",
                ["1.3.6.1.2.1.5.13"] = "icmpInAddrMaskReps",
                ["1.3.6.1.2.1.5.14"] = "icmpOutMsgs",
                ["1.3.6.1.2.1.5.15"] = "icmpOutErrors",
                ["1.3.6.1.2.1.5.16"] = "icmpOutDestUnreachs",
                ["1.3.6.1.2.1.5.17"] = "icmpOutTimeExcds",
                ["1.3.6.1.2.1.5.18"] = "icmpOutParmProbs",
                ["1.3.6.1.2.1.5.19"] = "icmpOutSrcQuenchs",
                ["1.3.6.1.2.1.5.20"] = "icmpOutRedirects",
                ["1.3.6.1.2.1.5.21"] = "icmpOutEchos",
                ["1.3.6.1.2.1.5.22"] = "icmpOutEchoReps",
                ["1.3.6.1.2.1.5.23"] = "icmpOutTimestamps",
                ["1.3.6.1.2.1.5.24"] = "icmpOutTimestampReps",
                ["1.3.6.1.2.1.5.25"] = "icmpOutAddrMasks",
                ["1.3.6.1.2.1.5.26"] = "icmpOutAddrMaskReps",
                ["1.3.6.1.2.1.5.29"] = "icmpStatsTable",
                ["1.3.6.1.2.1.5.29.1"] = "icmpStatsEntry",
                ["1.3.6.1.2.1.5.29.1.1"] = "icmpStatsIPVersion",
                ["1.3.6.1.2.1.5.29.1.2"] = "icmpStatsInMsgs",
                ["1.3.6.1.2.1.5.29.1.3"] = "icmpStatsInErrors",
                ["1.3.6.1.2.1.5.29.1.4"] = "icmpStatsOutMsgs",
                ["1.3.6.1.2.1.5.29.1.5"] = "icmpStatsOutErrors",
                ["1.3.6.1.2.1.5.30"] = "icmpMsgStatsTable",
                ["1.3.6.1.2.1.5.30.1"] = "icmpMsgStatsEntry",
                ["1.3.6.1.2.1.5.30.1.1"] = "icmpMsgStatsIPVersion",
                ["1.3.6.1.2.1.5.30.1.2"] = "icmpMsgStatsType",
                ["1.3.6.1.2.1.5.30.1.3"] = "icmpMsgStatsInPkts",
                ["1.3.6.1.2.1.5.30.1.4"] = "icmpMsgStatsOutPkts",
                ["1.3.6.1.2.1.6"] = "tcp",
                ["1.3.6.1.2.1.6.1"] = "tcpRtoAlgorithm",
                ["1.3.6.1.2.1.6.2"] = "tcpRtoMin",
                ["1.3.6.1.2.1.6.3"] = "tcpRtoMax",
                ["1.3.6.1.2.1.6.4"] = "tcpMaxConn",
                ["1.3.6.1.2.1.6.5"] = "tcpActiveOpens",
                ["1.3.6.1.2.1.6.6"] = "tcpPassiveOpens",
                ["1.3.6.1.2.1.6.7"] = "tcpAttemptFails",
                ["1.3.6.1.2.1.6.8"] = "tcpEstabResets",
                ["1.3.6.1.2.1.6.9"] = "tcpCurrEstab",
                ["1.3.6.1.2.1.6.10"] = "tcpInSegs",
                ["1.3.6.1.2.1.6.11"] = "tcpOutSegs",
                ["1.3.6.1.2.1.6.12"] = "tcpRetransSegs",
                ["1.3.6.1.2.1.6.13"] = "tcpConnTable",
                ["1.3.6.1.2.1.6.13.1"] = "tcpConnEntry",
                ["1.3.6.1.2.1.6.13.1.1"] = "tcpConnState",
                ["1.3.6.1.2.1.6.13.1.2"] = "tcpConnLocalAddress",
                ["1.3.6.1.2.1.6.13.1.3"] = "tcpConnLocalPort",
                ["1.3.6.1.2.1.6.13.1.4"] = "tcpConnRemAddress",
                ["1.3.6.1.2.1.6.13.1.5"] = "tcpConnRemPort",
                ["1.3.6.1.2.1.6.14"] = "tcpInErrs",
                ["1.3.6.1.2.1.6.15"] = "tcpOutRsts",
                ["1.3.6.1.2.1.6.16"] = "ipv6TcpConnTable",
                ["1.3.6.1.2.1.6.16.1"] = "ipv6TcpConnEntry",
                ["1.3.6.1.2.1.6.16.1.1"] = "ipv6TcpConnLocalAddress",
                ["1.3.6.1.2.1.6.16.1.2"] = "ipv6TcpConnLocalPort",
                ["1.3.6.1.2.1.6.16.1.3"] = "ipv6TcpConnRemAddress",
                ["1.3.6.1.2.1.6.16.1.4"] = "ipv6TcpConnRemPort",
                ["1.3.6.1.2.1.6.16.1.5"] = "ipv6TcpConnIfIndex",
                ["1.3.6.1.2.1.6.16.1.6"] = "ipv6TcpConnState",
                ["1.3.6.1.2.1.6.17"] = "tcpHCInSegs",
                ["1.3.6.1.2.1.6.18"] = "tcpHCOutSegs",
                ["1.3.6.1.2.1.6.19"] = "tcpConnectionTable",
                ["1.3.6.1.2.1.6.19.1"] = "tcpConnectionEntry",
                ["1.3.6.1.2.1.6.19.1.1"] = "tcpConnectionLocalAddressType",
                ["1.3.6.1.2.1.6.19.1.2"] = "tcpConnectionLocalAddress",
                ["1.3.6.1.2.1.6.19.1.3"] = "tcpConnectionLocalPort",
                ["1.3.6.1.2.1.6.19.1.4"] = "tcpConnectionRemAddressType",
                ["1.3.6.1.2.1.6.19.1.5"] = "tcpConnectionRemAddress",
                ["1.3.6.1.2.1.6.19.1.6"] = "tcpConnectionRemPort",
                ["1.3.6.1.2.1.6.19.1.7"] = "tcpConnectionState",
                ["1.3.6.1.2.1.6.19.1.8"] = "tcpConnectionProcess",
                ["1.3.6.1.2.1.6.20"] = "tcpListenerTable",
                ["1.3.6.1.2.1.6.20.1"] = "tcpListenerEntry",
                ["1.3.6.1.2.1.6.20.1.1"] = "tcpListenerLocalAddressType",
                ["1.3.6.1.2.1.6.20.1.2"] = "tcpListenerLocalAddress",
                ["1.3.6.1.2.1.6.20.1.3"] = "tcpListenerLocalPort",
                ["1.3.6.1.2.1.6.20.1.4"] = "tcpListenerProcess",
                ["1.3.6.1.2.1.7"] = "udp",
                ["1.3.6.1.2.1.7.1"] = "udpInDatagrams",
                ["1.3.6.1.2.1.7.2"] = "udpNoPorts",
                ["1.3.6.1.2.1.7.3"] = "udpInErrors",
                ["1.3.6.1.2.1.7.4"] = "udpOutDatagrams",
                ["1.3.6.1.2.1.7.5"] = "udpTable",
                ["1.3.6.1.2.1.7.5.1"] = "udpEntry",
                ["1.3.6.1.2.1.7.5.1.1"] = "udpLocalAddress",
                ["1.3.6.1.2.1.7.5.1.2"] = "udpLocalPort",
                ["1.3.6.1.2.1.7.6"] = "ipv6UdpTable",
                ["1.3.6.1.2.1.7.6.1"] = "ipv6UdpEntry",
                ["1.3.6.1.2.1.7.6.1.1"] = "ipv6UdpLocalAddress",
                ["1.3.6.1.2.1.7.6.1.2"] = "ipv6UdpLocalPort",
                ["1.3.6.1.2.1.7.6.1.3"] = "ipv6UdpIfIndex",
                ["1.3.6.1.2.1.7.7"] = "udpEndpointTable",
                ["1.3.6.1.2.1.7.7.1"] = "udpEndpointEntry",
                ["1.3.6.1.2.1.7.7.1.1"] = "udpEndpointLocalAddressType",
                ["1.3.6.1.2.1.7.7.1.2"] = "udpEndpointLocalAddress",
                ["1.3.6.1.2.1.7.7.1.3"] = "udpEndpointLocalPort",
                ["1.3.6.1.2.1.7.7.1.4"] = "udpEndpointRemoteAddressType",
                ["1.3.6.1.2.1.7.7.1.5"] = "udpEndpointRemoteAddress",
                ["1.3.6.1.2.1.7.7.1.6"] = "udpEndpointRemotePort",
                ["1.3.6.1.2.1.7.7.1.7"] = "udpEndpointInstance",
                ["1.3.6.1.2.1.7.7.1.8"] = "udpEndpointProcess",
                ["1.3.6.1.2.1.7.8"] = "udpHCInDatagrams",
                ["1.3.6.1.2.1.7.9"] = "udpHCOutDatagrams",
                ["1.3.6.1.2.1.8"] = "egp",
                ["1.3.6.1.2.1.8.1"] = "egpInMsgs",
                ["1.3.6.1.2.1.8.2"] = "egpInErrors",
                ["1.3.6.1.2.1.8.3"] = "egpOutMsgs",
                ["1.3.6.1.2.1.8.4"] = "egpOutErrors",
                ["1.3.6.1.2.1.8.5"] = "egpNeighTable",
                ["1.3.6.1.2.1.8.5.1"] = "egpNeighEntry",
                ["1.3.6.1.2.1.8.5.1.1"] = "egpNeighState",
                ["1.3.6.1.2.1.8.5.1.2"] = "egpNeighAddr",
                ["1.3.6.1.2.1.8.5.1.3"] = "egpNeighAs",
                ["1.3.6.1.2.1.8.5.1.4"] = "egpNeighInMsgs",
                ["1.3.6.1.2.1.8.5.1.5"] = "egpNeighInErrs",
                ["1.3.6.1.2.1.8.5.1.6"] = "egpNeighOutMsgs",
                ["1.3.6.1.2.1.8.5.1.7"] = "egpNeighOutErrs",
                ["1.3.6.1.2.1.8.5.1.8"] = "egpNeighInErrMsgs",
                ["1.3.6.1.2.1.8.5.1.9"] = "egpNeighOutErrMsgs",
                ["1.3.6.1.2.1.8.5.1.10"] = "egpNeighStateUps",
                ["1.3.6.1.2.1.8.5.1.11"] = "egpNeighStateDowns",
                ["1.3.6.1.2.1.8.5.1.12"] = "egpNeighIntervalHello",
                ["1.3.6.1.2.1.8.5.1.13"] = "egpNeighIntervalPoll",
                ["1.3.6.1.2.1.8.5.1.14"] = "egpNeighMode",
                ["1.3.6.1.2.1.8.5.1.15"] = "egpNeighEventTrigger",
                ["1.3.6.1.2.1.8.6"] = "egpAs",
                ["1.3.6.1.2.1.10"] = "transmission",
                ["1.3.6.1.2.1.11"] = "snmp",
                ["1.3.6.1.2.1.11.1"] = "snmpInPkts",
                ["1.3.6.1.2.1.11.2"] = "snmpOutPkts",
                ["1.3.6.1.2.1.11.3"] = "snmpInBadVersions",
                ["1.3.6.1.2.1.11.4"] = "snmpInBadCommunityNames",
                ["1.3.6.1.2.1.11.5"] = "snmpInBadCommunityUses",
                ["1.3.6.1.2.1.11.6"] = "snmpInASNParseErrs",
                ["1.3.6.1.2.1.11.8"] = "snmpInTooBigs",
                ["1.3.6.1.2.1.11.9"] = "snmpInNoSuchNames",
                ["1.3.6.1.2.1.11.10"] = "snmpInBadValues",
                ["1.3.6.1.2.1.11.11"] = "snmpInReadOnlys",
                ["1.3.6.1.2.1.11.12"] = "snmpInGenErrs",
                ["1.3.6.1.2.1.11.13"] = "snmpInTotalReqVars",
                ["1.3.6.1.2.1.11.14"] = "snmpInTotalSetVars",
                ["1.3.6.1.2.1.11.15"] = "snmpInGetRequests",
                ["1.3.6.1.2.1.11.16"] = "snmpInGetNexts",
                ["1.3.6.1.2.1.11.17"] = "snmpInSetRequests",
                ["1.3.6.1.2.1.11.18"] = "snmpInGetResponses",
                ["1.3.6.1.2.1.11.19"] = "snmpInTraps",
                ["1.3.6.1.2.1.11.20"] = "snmpOutTooBigs",
                ["1.3.6.1.2.1.11.21"] = "snmpOutNoSuchNames",
                ["1.3.6.1.2.1.11.22"] = "snmpOutBadValues",
                ["1.3.6.1.2.1.11.24"] = "snmpOutGenErrs",
                ["1.3.6.1.2.1.11.25"] = "snmpOutGetRequests",
                ["1.3.6.1.2.1.11.26"] = "snmpOutGetNexts",
                ["1.3.6.1.2.1.11.27"] = "snmpOutSetRequests",
                ["1.3.6.1.2.1.11.28"] = "snmpOutGetResponses",
                ["1.3.6.1.2.1.11.29"] = "snmpOutTraps",
                ["1.3.6.1.2.1.11.30"] = "snmpEnableAuthenTraps",
                ["1.3.6.1.2.1.11.31"] = "snmpSilentDrops",
                ["1.3.6.1.2.1.11.32"] = "snmpProxyDrops",
                ["1.3.6.1.2.1.25"] = "host",
                ["1.3.6.1.2.1.25.1"] = "hrSystem",
                ["1.3.6.1.2.1.25.1.1"] = "hrSystemUptime",
                ["1.3.6.1.2.1.25.1.2"] = "hrSystemDate",
                ["1.3.6.1.2.1.25.1.3"] = "hrSystemInitialLoadDevice",
                ["1.3.6.1.2.1.25.1.4"] = "hrSystemInitialLoadParameters",
                ["1.3.6.1.2.1.25.1.5"] = "hrSystemNumUsers",
                ["1.3.6.1.2.1.25.1.6"] = "hrSystemProcesses",
                ["1.3.6.1.2.1.25.1.7"] = "hrSystemMaxProcesses",
                ["1.3.6.1.2.1.25.2"] = "hrStorage",
                ["1.3.6.1.2.1.25.2.1"] = "hrStorageTypes",
                ["1.3.6.1.2.1.25.2.1.1"] = "hrStorageOther",
                ["1.3.6.1.2.1.25.2.1.2"] = "hrStorageRam",
                ["1.3.6.1.2.1.25.2.1.3"] = "hrStorageVirtualMemory",
                ["1.3.6.1.2.1.25.2.1.4"] = "hrStorageFixedDisk",
                ["1.3.6.1.2.1.25.2.1.5"] = "hrStorageRemovableDisk",
                ["1.3.6.1.2.1.25.2.1.6"] = "hrStorageFloppyDisk",
                ["1.3.6.1.2.1.25.2.1.7"] = "hrStorageCompactDisc",
                ["1.3.6.1.2.1.25.2.1.8"] = "hrStorageRamDisk",
                ["1.3.6.1.2.1.25.2.1.9"] = "hrStorageFlashMemory",
                ["1.3.6.1.2.1.25.2.1.10"] = "hrStorageNetworkDisk",
                ["1.3.6.1.2.1.25.2.2"] = "hrMemorySize",
                ["1.3.6.1.2.1.25.2.3"] = "hrStorageTable",
                ["1.3.6.1.2.1.25.2.3.1"] = "hrStorageEntry",
                ["1.3.6.1.2.1.25.2.3.1.1"] = "hrStorageIndex",
                ["1.3.6.1.2.1.25.2.3.1.2"] = "hrStorageType",
                ["1.3.6.1.2.1.25.2.3.1.3"] = "hrStorageDescr",
                ["1.3.6.1.2.1.25.2.3.1.4"] = "hrStorageAllocationUnits",
                ["1.3.6.1.2.1.25.2.3.1.5"] = "hrStorageSize",
                ["1.3.6.1.2.1.25.2.3.1.6"] = "hrStorageUsed",
                ["1.3.6.1.2.1.25.2.3.1.7"] = "hrStorageAllocationFailures",
                ["1.3.6.1.2.1.25.3"] = "hrDevice",
                ["1.3.6.1.2.1.25.3.1"] = "hrDeviceTypes",
                ["1.3.6.1.2.1.25.3.1.1"] = "hrDeviceOther",
                ["1.3.6.1.2.1.25.3.1.2"] = "hrDeviceUnknown",
                ["1.3.6.1.2.1.25.3.1.3"] = "hrDeviceProcessor",
                ["1.3.6.1.2.1.25.3.1.4"] = "hrDeviceNetwork",
                ["1.3.6.1.2.1.25.3.1.5"] = "hrDevicePrinter",
                ["1.3.6.1.2.1.25.3.1.6"] = "hrDeviceDiskStorage",
                ["1.3.6.1.2.1.25.3.1.10"] = "hrDeviceVideo",
                ["1.3.6.1.2.1.25.3.1.11"] = "hrDeviceAudio",
                ["1.3.6.1.2.1.25.3.1.12"] = "hrDeviceCoprocessor",
                ["1.3.6.1.2.1.25.3.1.13"] = "hrDeviceKeyboard",
                ["1.3.6.1.2.1.25.3.1.14"] = "hrDeviceModem",
                ["1.3.6.1.2.1.25.3.1.15"] = "hrDeviceParallelPort",
                ["1.3.6.1.2.1.25.3.1.16"] = "hrDevicePointing",
                ["1.3.6.1.2.1.25.3.1.17"] = "hrDeviceSerialPort",
                ["1.3.6.1.2.1.25.3.1.18"] = "hrDeviceTape",
                ["1.3.6.1.2.1.25.3.1.19"] = "hrDeviceClock",
                ["1.3.6.1.2.1.25.3.1.20"] = "hrDeviceVolatileMemory",
                ["1.3.6.1.2.1.25.3.1.21"] = "hrDeviceNonVolatileMemory",
                ["1.3.6.1.2.1.25.3.2"] = "hrDeviceTable",
                ["1.3.6.1.2.1.25.3.2.1"] = "hrDeviceEntry",
                ["1.3.6.1.2.1.25.3.2.1.1"] = "hrDeviceIndex",
                ["1.3.6.1.2.1.25.3.2.1.2"] = "hrDeviceType",
                ["1.3.6.1.2.1.25.3.2.1.3"] = "hrDeviceDescr",
                ["1.3.6.1.2.1.25.3.2.1.4"] = "hrDeviceID",
                ["1.3.6.1.2.1.25.3.2.1.5"] = "hrDeviceStatus",
                ["1.3.6.1.2.1.25.3.2.1.6"] = "hrDeviceErrors",
                ["1.3.6.1.2.1.25.3.3"] = "hrProcessorTable",
                ["1.3.6.1.2.1.25.3.3.1"] = "hrProcessorEntry",
                ["1.3.6.1.2.1.25.3.3.1.1"] = "hrProcessorFrwID",
                ["1.3.6.1.2.1.25.3.3.1.2"] = "hrProcessorLoad",
                ["1.3.6.1.2.1.25.3.4"] = "hrNetworkTable",
                ["1.3.6.1.2.1.25.3.4.1"] = "hrNetworkEntry",
                ["1.3.6.1.2.1.25.3.4.1.1"] = "hrNetworkIfIndex",
                ["1.3.6.1.2.1.25.3.5"] = "hrPrinterTable",
                ["1.3.6.1.2.1.25.3.5.1"] = "hrPrinterEntry",
                ["1.3.6.1.2.1.25.3.5.1.1"] = "hrPrinterStatus",
                ["1.3.6.1.2.1.25.3.5.1.2"] = "hrPrinterDetectedErrorState",
                ["1.3.6.1.2.1.25.3.6"] = "hrDiskStorageTable",
                ["1.3.6.1.2.1.25.3.6.1"] = "hrDiskStorageEntry",
                ["1.3.6.1.2.1.25.3.6.1.1"] = "hrDiskStorageAccess",
                ["1.3.6.1.2.1.25.3.6.1.2"] = "hrDiskStorageMedia",
                ["1.3.6.1.2.1.25.3.6.1.3"] = "hrDiskStorageRemoveble",
                ["1.3.6.1.2.1.25.3.6.1.4"] = "hrDiskStorageCapacity",
                ["1.3.6.1.2.1.25.3.7"] = "hrPartitionTable",
                ["1.3.6.1.2.1.25.3.7.1"] = "hrPartitionEntry",
                ["1.3.6.1.2.1.25.3.7.1.1"] = "hrPartitionIndex",
                ["1.3.6.1.2.1.25.3.7.1.2"] = "hrPartitionLabel",
                ["1.3.6.1.2.1.25.3.7.1.3"] = "hrPartitionID",
                ["1.3.6.1.2.1.25.3.7.1.4"] = "hrPartitionSize",
                ["1.3.6.1.2.1.25.3.7.1.5"] = "hrPartitionFSIndex",
                ["1.3.6.1.2.1.25.3.8"] = "hrFSTable",
                ["1.3.6.1.2.1.25.3.8.1"] = "hrFSEntry",
                ["1.3.6.1.2.1.25.3.8.1.1"] = "hrFSIndex",
                ["1.3.6.1.2.1.25.3.8.1.2"] = "hrFSMountPoint",
                ["1.3.6.1.2.1.25.3.8.1.3"] = "hrFSRemoteMountPoint",
                ["1.3.6.1.2.1.25.3.8.1.4"] = "hrFSType",
                ["1.3.6.1.2.1.25.3.8.1.5"] = "hrFSAccess",
                ["1.3.6.1.2.1.25.3.8.1.6"] = "hrFSBootable",
                ["1.3.6.1.2.1.25.3.8.1.7"] = "hrFSStorageIndex",
                ["1.3.6.1.2.1.25.3.8.1.8"] = "hrFSLastFullBackupDate",
                ["1.3.6.1.2.1.25.3.8.1.9"] = "hrFSLastPartialBackupDate",
                ["1.3.6.1.2.1.25.3.9"] = "hrFSTypes",
                ["1.3.6.1.2.1.25.3.9.1"] = "hrFSOther",
                ["1.3.6.1.2.1.25.3.9.2"] = "hrFSUnknown",
                ["1.3.6.1.2.1.25.3.9.3"] = "hrFSBerkeleyFFS",
                ["1.3.6.1.2.1.25.3.9.4"] = "hrFSSys5FS",
                ["1.3.6.1.2.1.25.3.9.5"] = "hrFSFat",
                ["1.3.6.1.2.1.25.3.9.6"] = "hrFSHPFS",
                ["1.3.6.1.2.1.25.3.9.7"] = "hrFSHFS",
                ["1.3.6.1.2.1.25.3.9.8"] = "hrFSMFS",
                ["1.3.6.1.2.1.25.3.9.9"] = "hrFSNTFS",
                ["1.3.6.1.2.1.25.3.9.10"] = "hrFSVNode",
                ["1.3.6.1.2.1.25.3.9.11"] = "hrFSJournaled",
                ["1.3.6.1.2.1.25.3.9.12"] = "hrFSiso9660",
                ["1.3.6.1.2.1.25.3.9.13"] = "hrFSRockRidge",
                ["1.3.6.1.2.1.25.3.9.14"] = "hrFSNFS",
                ["1.3.6.1.2.1.25.3.9.15"] = "hrFSNetware",
                ["1.3.6.1.2.1.25.3.9.16"] = "hrFSAFS",
                ["1.3.6.1.2.1.25.3.9.17"] = "hrFSDFS",
                ["1.3.6.1.2.1.25.3.9.18"] = "hrFSAppleshare",
                ["1.3.6.1.2.1.25.3.9.19"] = "hrFSRFS",
                ["1.3.6.1.2.1.25.3.9.20"] = "hrFSDGCFS",
                ["1.3.6.1.2.1.25.3.9.21"] = "hrFSBFS",
                ["1.3.6.1.2.1.25.3.9.22"] = "hrFSFAT32",
                ["1.3.6.1.2.1.25.3.9.23"] = "hrFSLinuxExt2",
                ["1.3.6.1.2.1.25.4"] = "hrSWRun",
                ["1.3.6.1.2.1.25.4.1"] = "hrSWOSIndex",
                ["1.3.6.1.2.1.25.4.2"] = "hrSWRunTable",
                ["1.3.6.1.2.1.25.4.2.1"] = "hrSWRunEntry",
                ["1.3.6.1.2.1.25.4.2.1.1"] = "hrSWRunIndex",
                ["1.3.6.1.2.1.25.4.2.1.2"] = "hrSWRunName",
                ["1.3.6.1.2.1.25.4.2.1.3"] = "hrSWRunID",
                ["1.3.6.1.2.1.25.4.2.1.4"] = "hrSWRunPath",
                ["1.3.6.1.2.1.25.4.2.1.5"] = "hrSWRunParameters",
                ["1.3.6.1.2.1.25.4.2.1.6"] = "hrSWRunType",
                ["1.3.6.1.2.1.25.4.2.1.7"] = "hrSWRunStatus",
                ["1.3.6.1.2.1.25.5"] = "hrSWRunPerf",
                ["1.3.6.1.2.1.25.5.1"] = "hrSWRunPerfTable",
                ["1.3.6.1.2.1.25.5.1.1"] = "hrSWRunPerfEntry",
                ["1.3.6.1.2.1.25.5.1.1.1"] = "hrSWRunPerfCPU",
                ["1.3.6.1.2.1.25.5.1.1.2"] = "hrSWRunPerfMem",
                ["1.3.6.1.2.1.25.6"] = "hrSWInstalled",
                ["1.3.6.1.2.1.25.6.1"] = "hrSWInstalledLastChange",
                ["1.3.6.1.2.1.25.6.2"] = "hrSWInstalledLastUpdateTime",
                ["1.3.6.1.2.1.25.6.3"] = "hrSWInstalledTable",
                ["1.3.6.1.2.1.25.6.3.1"] = "hrSWInstalledEntry",
                ["1.3.6.1.2.1.25.6.3.1.1"] = "hrSWInstalledIndex",
                ["1.3.6.1.2.1.25.6.3.1.2"] = "hrSWInstalledName",
                ["1.3.6.1.2.1.25.6.3.1.3"] = "hrSWInstalledID",
                ["1.3.6.1.2.1.25.6.3.1.4"] = "hrSWInstalledType",
                ["1.3.6.1.2.1.25.6.3.1.5"] = "hrSWInstalledDate",
                ["1.3.6.1.2.1.25.7"] = "hrMIBAdminInfo",
                ["1.3.6.1.2.1.25.7.1"] = "hostResourcesMibModule",
                ["1.3.6.1.2.1.25.7.2"] = "hrMIBCompliances",
                ["1.3.6.1.2.1.25.7.2.1"] = "hrMIBCompliance",
                ["1.3.6.1.2.1.25.7.3"] = "hrMIBGroups",
                ["1.3.6.1.2.1.25.7.3.1"] = "hrSystemGroup",
                ["1.3.6.1.2.1.25.7.3.2"] = "hrStorageGroup",
                ["1.3.6.1.2.1.25.7.3.3"] = "hrDeviceGroup",
                ["1.3.6.1.2.1.25.7.3.4"] = "hrSWRunGroup",
                ["1.3.6.1.2.1.25.7.3.5"] = "hrSWRunPerfGroup",
                ["1.3.6.1.2.1.25.7.3.6"] = "hrSWInstalledGroup",
                ["1.3.6.1.2.1.25.7.4"] = "hostResourcesTypesModule",
                ["1.3.6.1.2.1.27"] = "application",
                ["1.3.6.1.2.1.27.1"] = "applTable",
                ["1.3.6.1.2.1.27.1.1"] = "applEntry",
                ["1.3.6.1.2.1.27.1.1.1"] = "applIndex",
                ["1.3.6.1.2.1.27.1.1.2"] = "applName",
                ["1.3.6.1.2.1.27.1.1.3"] = "applDirectoryName",
                ["1.3.6.1.2.1.27.1.1.4"] = "applVersion",
                ["1.3.6.1.2.1.27.1.1.5"] = "applUptime",
                ["1.3.6.1.2.1.27.1.1.6"] = "applOperStatus",
                ["1.3.6.1.2.1.27.1.1.7"] = "applLastChange",
                ["1.3.6.1.2.1.27.1.1.8"] = "applInboundAssociations",
                ["1.3.6.1.2.1.27.1.1.9"] = "applOutboundAssociations",
                ["1.3.6.1.2.1.27.1.1.10"] = "applAccumulatedInboundAssociations",
                ["1.3.6.1.2.1.27.1.1.11"] = "applAccumulatedOutboundAssociations",
                ["1.3.6.1.2.1.27.1.1.12"] = "applLastInboundActivity",
                ["1.3.6.1.2.1.27.1.1.13"] = "applLastOutboundActivity",
                ["1.3.6.1.2.1.27.1.1.14"] = "applRejectedInboundAssociations",
                ["1.3.6.1.2.1.27.1.1.15"] = "applFailedOutboundAssociations",
                ["1.3.6.1.2.1.27.1.1.16"] = "applDescription",
                ["1.3.6.1.2.1.27.1.1.17"] = "applURL",
                ["1.3.6.1.2.1.27.2"] = "assocTable",
                ["1.3.6.1.2.1.27.2.1"] = "assocEntry",
                ["1.3.6.1.2.1.27.2.1.1"] = "assocIndex",
                ["1.3.6.1.2.1.27.2.1.2"] = "assocRemoteApplication",
                ["1.3.6.1.2.1.27.2.1.3"] = "assocApplicationProtocol",
                ["1.3.6.1.2.1.27.2.1.4"] = "assocApplicationType",
                ["1.3.6.1.2.1.27.2.1.5"] = "assocDuration",
                ["1.3.6.1.2.1.27.3"] = "applConformance",
                ["1.3.6.1.2.1.27.3.1"] = "applGroups",
                ["1.3.6.1.2.1.27.3.1.2"] = "assocRFC1565Group",
                ["1.3.6.1.2.1.27.3.1.3"] = "applRFC2248Group",
                ["1.3.6.1.2.1.27.3.1.4"] = "assocRFC2248Group",
                ["1.3.6.1.2.1.27.3.1.5"] = "applRFC2788Group",
                ["1.3.6.1.2.1.27.3.1.6"] = "assocRFC2788Group",
                ["1.3.6.1.2.1.27.3.1.7"] = "applRFC1565Group",
                ["1.3.6.1.2.1.27.3.2"] = "applCompliances",
                ["1.3.6.1.2.1.27.3.2.1"] = "applCompliance",
                ["1.3.6.1.2.1.27.3.2.2"] = "assocCompliance",
                ["1.3.6.1.2.1.27.3.2.3"] = "applRFC2248Compliance",
                ["1.3.6.1.2.1.27.3.2.4"] = "assocRFC2248Compliance",
                ["1.3.6.1.2.1.27.3.2.5"] = "applRFC2788Compliance",
                ["1.3.6.1.2.1.27.3.2.6"] = "assocRFC2788Compliance",
                ["1.3.6.1.2.1.27.4"] = "applTCPProtoID",
                ["1.3.6.1.2.1.27.5"] = "applUDPProtoID",
                ["1.3.6.1.2.1.28"] = "mta",
                ["1.3.6.1.2.1.28.1"] = "mtaTable",
                ["1.3.6.1.2.1.28.1.1"] = "mtaEntry",
                ["1.3.6.1.2.1.28.1.1.1"] = "mtaReceivedMessages",
                ["1.3.6.1.2.1.28.1.1.2"] = "mtaStoredMessages",
                ["1.3.6.1.2.1.28.1.1.3"] = "mtaTransmittedMessages",
                ["1.3.6.1.2.1.28.1.1.4"] = "mtaReceivedVolume",
                ["1.3.6.1.2.1.28.1.1.5"] = "mtaStoredVolume",
                ["1.3.6.1.2.1.28.1.1.6"] = "mtaTransmittedVolume",
                ["1.3.6.1.2.1.28.1.1.7"] = "mtaReceivedRecipients",
                ["1.3.6.1.2.1.28.1.1.8"] = "mtaStoredRecipients",
                ["1.3.6.1.2.1.28.1.1.9"] = "mtaTransmittedRecipients",
                ["1.3.6.1.2.1.28.1.1.10"] = "mtaSuccessfulConvertedMessages",
                ["1.3.6.1.2.1.28.1.1.11"] = "mtaFailedConvertedMessages",
                ["1.3.6.1.2.1.28.1.1.12"] = "mtaLoopsDetected",
                ["1.3.6.1.2.1.28.2"] = "mtaGroupTable",
                ["1.3.6.1.2.1.28.2.1"] = "mtaGroupEntry",
                ["1.3.6.1.2.1.28.2.1.1"] = "mtaGroupIndex",
                ["1.3.6.1.2.1.28.2.1.2"] = "mtaGroupReceivedMessages",
                ["1.3.6.1.2.1.28.2.1.3"] = "mtaGroupRejectedMessages",
                ["1.3.6.1.2.1.28.2.1.4"] = "mtaGroupStoredMessages",
                ["1.3.6.1.2.1.28.2.1.5"] = "mtaGroupTransmittedMessages",
                ["1.3.6.1.2.1.28.2.1.6"] = "mtaGroupReceivedVolume",
                ["1.3.6.1.2.1.28.2.1.7"] = "mtaGroupStoredVolume",
                ["1.3.6.1.2.1.28.2.1.8"] = "mtaGroupTransmittedVolume",
                ["1.3.6.1.2.1.28.2.1.9"] = "mtaGroupReceivedRecipients",
                ["1.3.6.1.2.1.28.2.1.10"] = "mtaGroupStoredRecipients",
                ["1.3.6.1.2.1.28.2.1.11"] = "mtaGroupTransmittedRecipients",
                ["1.3.6.1.2.1.28.2.1.12"] = "mtaGroupOldestMessageStored",
                ["1.3.6.1.2.1.28.2.1.13"] = "mtaGroupInboundAssociations",
                ["1.3.6.1.2.1.28.2.1.14"] = "mtaGroupOutboundAssociations",
                ["1.3.6.1.2.1.28.2.1.15"] = "mtaGroupAccumulatedInboundAssociations",
                ["1.3.6.1.2.1.28.2.1.16"] = "mtaGroupAccumulatedOutboundAssociations",
                ["1.3.6.1.2.1.28.2.1.17"] = "mtaGroupLastInboundActivity",
                ["1.3.6.1.2.1.28.2.1.18"] = "mtaGroupLastOutboundActivity",
                ["1.3.6.1.2.1.28.2.1.19"] = "mtaGroupRejectedInboundAssociations",
                ["1.3.6.1.2.1.28.2.1.20"] = "mtaGroupFailedOutboundAssociations",
                ["1.3.6.1.2.1.28.2.1.21"] = "mtaGroupInboundRejectionReason",
                ["1.3.6.1.2.1.28.2.1.22"] = "mtaGroupOutboundConnectFailureReason",
                ["1.3.6.1.2.1.28.2.1.23"] = "mtaGroupScheduledRetry",
                ["1.3.6.1.2.1.28.2.1.24"] = "mtaGroupMailProtocol",
                ["1.3.6.1.2.1.28.2.1.25"] = "mtaGroupName",
                ["1.3.6.1.2.1.28.2.1.26"] = "mtaGroupSuccessfulConvertedMessages",
                ["1.3.6.1.2.1.28.2.1.27"] = "mtaGroupFailedConvertedMessages",
                ["1.3.6.1.2.1.28.2.1.28"] = "mtaGroupDescription",
                ["1.3.6.1.2.1.28.2.1.29"] = "mtaGroupURL",
                ["1.3.6.1.2.1.28.2.1.30"] = "mtaGroupCreationTime",
                ["1.3.6.1.2.1.28.2.1.31"] = "mtaGroupHierarchy",
                ["1.3.6.1.2.1.28.2.1.32"] = "mtaGroupOldestMessageId",
                ["1.3.6.1.2.1.28.2.1.33"] = "mtaGroupLoopsDetected",
                ["1.3.6.1.2.1.28.2.1.34"] = "mtaGroupLastOutboundAssociationAttempt",
                ["1.3.6.1.2.1.28.3"] = "mtaGroupAssociationTable",
                ["1.3.6.1.2.1.28.3.1"] = "mtaGroupAssociationEntry",
                ["1.3.6.1.2.1.28.3.1.1"] = "mtaGroupAssociationIndex",
                ["1.3.6.1.2.1.28.4"] = "mtaConformance",
                ["1.3.6.1.2.1.28.4.1"] = "mtaGroups",
                ["1.3.6.1.2.1.28.4.1.4"] = "mtaRFC2249Group",
                ["1.3.6.1.2.1.28.4.1.5"] = "mtaRFC2249AssocGroup",
                ["1.3.6.1.2.1.28.4.1.6"] = "mtaRFC2249ErrorGroup",
                ["1.3.6.1.2.1.28.4.1.7"] = "mtaRFC2789Group",
                ["1.3.6.1.2.1.28.4.1.8"] = "mtaRFC2789AssocGroup",
                ["1.3.6.1.2.1.28.4.1.9"] = "mtaRFC2789ErrorGroup",
                ["1.3.6.1.2.1.28.4.1.10"] = "mtaRFC1566Group",
                ["1.3.6.1.2.1.28.4.1.11"] = "mtaRFC1566AssocGroup",
                ["1.3.6.1.2.1.28.4.2"] = "mtaCompliances",
                ["1.3.6.1.2.1.28.4.2.1"] = "mtaCompliance",
                ["1.3.6.1.2.1.28.4.2.2"] = "mtaAssocCompliance",
                ["1.3.6.1.2.1.28.4.2.5"] = "mtaRFC2249Compliance",
                ["1.3.6.1.2.1.28.4.2.6"] = "mtaRFC2249AssocCompliance",
                ["1.3.6.1.2.1.28.4.2.7"] = "mtaRFC2249ErrorCompliance",
                ["1.3.6.1.2.1.28.4.2.8"] = "mtaRFC2249FullCompliance",
                ["1.3.6.1.2.1.28.4.2.9"] = "mtaRFC2789Compliance",
                ["1.3.6.1.2.1.28.4.2.10"] = "mtaRFC2789AssocCompliance",
                ["1.3.6.1.2.1.28.4.2.11"] = "mtaRFC2789ErrorCompliance",
                ["1.3.6.1.2.1.28.4.2.12"] = "mtaRFC2789FullCompliance",
                ["1.3.6.1.2.1.28.5"] = "mtaGroupErrorTable",
                ["1.3.6.1.2.1.28.5.1"] = "mtaGroupErrorEntry",
                ["1.3.6.1.2.1.28.5.1.1"] = "mtaGroupInboundErrorCount",
                ["1.3.6.1.2.1.28.5.1.2"] = "mtaGroupInternalErrorCount",
                ["1.3.6.1.2.1.28.5.1.3"] = "mtaGroupOutboundErrorCount",
                ["1.3.6.1.2.1.28.5.1.4"] = "mtaStatusCode",
                ["1.3.6.1.2.1.30"] = "ianaifType",
                ["1.3.6.1.2.1.31"] = "ifMIB",
                ["1.3.6.1.2.1.31.1"] = "ifMIBObjects",
                ["1.3.6.1.2.1.31.1.1"] = "ifXTable",
                ["1.3.6.1.2.1.31.1.1.1"] = "ifXEntry",
                ["1.3.6.1.2.1.31.1.1.1.1"] = "ifName",
                ["1.3.6.1.2.1.31.1.1.1.2"] = "ifInMulticastPkts",
                ["1.3.6.1.2.1.31.1.1.1.3"] = "ifInBroadcastPkts",
                ["1.3.6.1.2.1.31.1.1.1.4"] = "ifOutMulticastPkts",
                ["1.3.6.1.2.1.31.1.1.1.5"] = "ifOutBroadcastPkts",
                ["1.3.6.1.2.1.31.1.1.1.6"] = "ifHCInOctets",
                ["1.3.6.1.2.1.31.1.1.1.7"] = "ifHCInUcastPkts",
                ["1.3.6.1.2.1.31.1.1.1.8"] = "ifHCInMulticastPkts",
                ["1.3.6.1.2.1.31.1.1.1.9"] = "ifHCInBroadcastPkts",
                ["1.3.6.1.2.1.31.1.1.1.10"] = "ifHCOutOctets",
                ["1.3.6.1.2.1.31.1.1.1.11"] = "ifHCOutUcastPkts",
                ["1.3.6.1.2.1.31.1.1.1.12"] = "ifHCOutMulticastPkts",
                ["1.3.6.1.2.1.31.1.1.1.13"] = "ifHCOutBroadcastPkts",
                ["1.3.6.1.2.1.31.1.1.1.14"] = "ifLinkUpDownTrapEnable",
                ["1.3.6.1.2.1.31.1.1.1.15"] = "ifHighSpeed",
                ["1.3.6.1.2.1.31.1.1.1.16"] = "ifPromiscuousMode",
                ["1.3.6.1.2.1.31.1.1.1.17"] = "ifConnectorPresent",
                ["1.3.6.1.2.1.31.1.1.1.18"] = "ifAlias",
                ["1.3.6.1.2.1.31.1.1.1.19"] = "ifCounterDiscontinuityTime",
                ["1.3.6.1.2.1.31.1.2"] = "ifStackTable",
                ["1.3.6.1.2.1.31.1.2.1"] = "ifStackEntry",
                ["1.3.6.1.2.1.31.1.2.1.1"] = "ifStackHigherLayer",
                ["1.3.6.1.2.1.31.1.2.1.2"] = "ifStackLowerLayer",
                ["1.3.6.1.2.1.31.1.2.1.3"] = "ifStackStatus",
                ["1.3.6.1.2.1.31.1.3"] = "ifTestTable",
                ["1.3.6.1.2.1.31.1.3.1"] = "ifTestEntry",
                ["1.3.6.1.2.1.31.1.3.1.1"] = "ifTestId",
                ["1.3.6.1.2.1.31.1.3.1.2"] = "ifTestStatus",
                ["1.3.6.1.2.1.31.1.3.1.3"] = "ifTestType",
                ["1.3.6.1.2.1.31.1.3.1.4"] = "ifTestResult",
                ["1.3.6.1.2.1.31.1.3.1.5"] = "ifTestCode",
                ["1.3.6.1.2.1.31.1.3.1.6"] = "ifTestOwner",
                ["1.3.6.1.2.1.31.1.4"] = "ifRcvAddressTable",
                ["1.3.6.1.2.1.31.1.4.1"] = "ifRcvAddressEntry",
                ["1.3.6.1.2.1.31.1.4.1.1"] = "ifRcvAddressAddress",
                ["1.3.6.1.2.1.31.1.4.1.2"] = "ifRcvAddressStatus",
                ["1.3.6.1.2.1.31.1.4.1.3"] = "ifRcvAddressType",
                ["1.3.6.1.2.1.31.1.5"] = "ifTableLastChange",
                ["1.3.6.1.2.1.31.1.6"] = "ifStackLastChange",
                ["1.3.6.1.2.1.31.2"] = "ifConformance",
                ["1.3.6.1.2.1.31.2.1"] = "ifGroups",
                ["1.3.6.1.2.1.31.2.1.1"] = "ifGeneralGroup",
                ["1.3.6.1.2.1.31.2.1.2"] = "ifFixedLengthGroup",
                ["1.3.6.1.2.1.31.2.1.3"] = "ifHCFixedLengthGroup",
                ["1.3.6.1.2.1.31.2.1.4"] = "ifPacketGroup",
                ["1.3.6.1.2.1.31.2.1.5"] = "ifHCPacketGroup",
                ["1.3.6.1.2.1.31.2.1.6"] = "ifVHCPacketGroup",
                ["1.3.6.1.2.1.31.2.1.7"] = "ifRcvAddressGroup",
                ["1.3.6.1.2.1.31.2.1.8"] = "ifTestGroup",
                ["1.3.6.1.2.1.31.2.1.9"] = "ifStackGroup",
                ["1.3.6.1.2.1.31.2.1.10"] = "ifGeneralInformationGroup",
                ["1.3.6.1.2.1.31.2.1.11"] = "ifStackGroup2",
                ["1.3.6.1.2.1.31.2.1.12"] = "ifOldObjectsGroup",
                ["1.3.6.1.2.1.31.2.1.13"] = "ifCounterDiscontinuityGroup",
                ["1.3.6.1.2.1.31.2.1.14"] = "linkUpDownNotificationsGroup",
                ["1.3.6.1.2.1.31.2.2"] = "ifCompliances",
                ["1.3.6.1.2.1.31.2.2.1"] = "ifCompliance",
                ["1.3.6.1.2.1.31.2.2.2"] = "ifCompliance2",
                ["1.3.6.1.2.1.31.2.2.3"] = "ifCompliance3",
                ["1.3.6.1.2.1.48"] = "ipMIB",
                ["1.3.6.1.2.1.48.2"] = "ipMIBConformance",
                ["1.3.6.1.2.1.48.2.1"] = "ipMIBCompliances",
                ["1.3.6.1.2.1.48.2.1.1"] = "ipMIBCompliance",
                ["1.3.6.1.2.1.48.2.1.2"] = "ipMIBCompliance2",
                ["1.3.6.1.2.1.48.2.2"] = "ipMIBGroups",
                ["1.3.6.1.2.1.48.2.2.1"] = "ipGroup",
                ["1.3.6.1.2.1.48.2.2.2"] = "icmpGroup",
                ["1.3.6.1.2.1.48.2.2.3"] = "ipv4GeneralGroup",
                ["1.3.6.1.2.1.48.2.2.4"] = "ipv4IfGroup",
                ["1.3.6.1.2.1.48.2.2.5"] = "ipv6GeneralGroup2",
                ["1.3.6.1.2.1.48.2.2.6"] = "ipv6IfGroup",
                ["1.3.6.1.2.1.48.2.2.7"] = "ipLastChangeGroup",
                ["1.3.6.1.2.1.48.2.2.8"] = "ipSystemStatsGroup",
                ["1.3.6.1.2.1.48.2.2.9"] = "ipv4SystemStatsGroup",
                ["1.3.6.1.2.1.48.2.2.10"] = "ipSystemStatsHCOctetGroup",
                ["1.3.6.1.2.1.48.2.2.11"] = "ipSystemStatsHCPacketGroup",
                ["1.3.6.1.2.1.48.2.2.12"] = "ipv4SystemStatsHCPacketGroup",
                ["1.3.6.1.2.1.48.2.2.13"] = "ipIfStatsGroup",
                ["1.3.6.1.2.1.48.2.2.14"] = "ipv4IfStatsGroup",
                ["1.3.6.1.2.1.48.2.2.15"] = "ipIfStatsHCOctetGroup",
                ["1.3.6.1.2.1.48.2.2.16"] = "ipIfStatsHCPacketGroup",
                ["1.3.6.1.2.1.48.2.2.17"] = "ipv4IfStatsHCPacketGroup",
                ["1.3.6.1.2.1.48.2.2.18"] = "ipAddressPrefixGroup",
                ["1.3.6.1.2.1.48.2.2.19"] = "ipAddressGroup",
                ["1.3.6.1.2.1.48.2.2.20"] = "ipNetToPhysicalGroup",
                ["1.3.6.1.2.1.48.2.2.21"] = "ipv6ScopeGroup",
                ["1.3.6.1.2.1.48.2.2.22"] = "ipDefaultRouterGroup",
                ["1.3.6.1.2.1.48.2.2.23"] = "ipv6RouterAdvertGroup",
                ["1.3.6.1.2.1.48.2.2.24"] = "icmpStatsGroup",
                ["1.3.6.1.2.1.49"] = "tcpMIB",
                ["1.3.6.1.2.1.49.2"] = "tcpMIBConformance",
                ["1.3.6.1.2.1.49.2.1"] = "tcpMIBCompliances",
                ["1.3.6.1.2.1.49.2.1.1"] = "tcpMIBCompliance",
                ["1.3.6.1.2.1.49.2.1.2"] = "tcpMIBCompliance2",
                ["1.3.6.1.2.1.49.2.2"] = "tcpMIBGroups",
                ["1.3.6.1.2.1.49.2.2.1"] = "tcpGroup",
                ["1.3.6.1.2.1.49.2.2.2"] = "tcpBaseGroup",
                ["1.3.6.1.2.1.49.2.2.3"] = "tcpConnectionGroup",
                ["1.3.6.1.2.1.49.2.2.4"] = "tcpListenerGroup",
                ["1.3.6.1.2.1.49.2.2.5"] = "tcpHCGroup",
                ["1.3.6.1.2.1.50"] = "udpMIB",
                ["1.3.6.1.2.1.50.2"] = "udpMIBConformance",
                ["1.3.6.1.2.1.50.2.1"] = "udpMIBCompliances",
                ["1.3.6.1.2.1.50.2.1.1"] = "udpMIBCompliance",
                ["1.3.6.1.2.1.50.2.1.2"] = "udpMIBCompliance2",
                ["1.3.6.1.2.1.50.2.2"] = "udpMIBGroups",
                ["1.3.6.1.2.1.50.2.2.1"] = "udpGroup",
                ["1.3.6.1.2.1.50.2.2.2"] = "udpBaseGroup",
                ["1.3.6.1.2.1.50.2.2.3"] = "udpHCGroup",
                ["1.3.6.1.2.1.50.2.2.4"] = "udpEndpointGroup",
                ["1.3.6.1.2.1.55"] = "ipv6MIB",
                ["1.3.6.1.2.1.55.1"] = "ipv6MIBObjects",
                ["1.3.6.1.2.1.55.1.1"] = "ipv6Forwarding",
                ["1.3.6.1.2.1.55.1.2"] = "ipv6DefaultHopLimit",
                ["1.3.6.1.2.1.55.1.3"] = "ipv6Interfaces",
                ["1.3.6.1.2.1.55.1.4"] = "ipv6IfTableLastChange",
                ["1.3.6.1.2.1.55.1.5"] = "ipv6IfTable",
                ["1.3.6.1.2.1.55.1.5.1"] = "ipv6IfEntry",
                ["1.3.6.1.2.1.55.1.5.1.1"] = "ipv6IfIndex",
                ["1.3.6.1.2.1.55.1.5.1.2"] = "ipv6IfDescr",
                ["1.3.6.1.2.1.55.1.5.1.3"] = "ipv6IfLowerLayer",
                ["1.3.6.1.2.1.55.1.5.1.4"] = "ipv6IfEffectiveMtu",
                ["1.3.6.1.2.1.55.1.5.1.5"] = "ipv6IfReasmMaxSize",
                ["1.3.6.1.2.1.55.1.5.1.6"] = "ipv6IfIdentifier",
                ["1.3.6.1.2.1.55.1.5.1.7"] = "ipv6IfIdentifierLength",
                ["1.3.6.1.2.1.55.1.5.1.8"] = "ipv6IfPhysicalAddress",
                ["1.3.6.1.2.1.55.1.5.1.9"] = "ipv6IfAdminStatus",
                ["1.3.6.1.2.1.55.1.5.1.10"] = "ipv6IfOperStatus",
                ["1.3.6.1.2.1.55.1.5.1.11"] = "ipv6IfLastChange",
                ["1.3.6.1.2.1.55.1.6"] = "ipv6IfStatsTable",
                ["1.3.6.1.2.1.55.1.6.1"] = "ipv6IfStatsEntry",
                ["1.3.6.1.2.1.55.1.6.1.1"] = "ipv6IfStatsInReceives",
                ["1.3.6.1.2.1.55.1.6.1.2"] = "ipv6IfStatsInHdrErrors",
                ["1.3.6.1.2.1.55.1.6.1.3"] = "ipv6IfStatsInTooBigErrors",
                ["1.3.6.1.2.1.55.1.6.1.4"] = "ipv6IfStatsInNoRoutes",
                ["1.3.6.1.2.1.55.1.6.1.5"] = "ipv6IfStatsInAddrErrors",
                ["1.3.6.1.2.1.55.1.6.1.6"] = "ipv6IfStatsInUnknownProtos",
                ["1.3.6.1.2.1.55.1.6.1.7"] = "ipv6IfStatsInTruncatedPkts",
                ["1.3.6.1.2.1.55.1.6.1.8"] = "ipv6IfStatsInDiscards",
                ["1.3.6.1.2.1.55.1.6.1.9"] = "ipv6IfStatsInDelivers",
                ["1.3.6.1.2.1.55.1.6.1.10"] = "ipv6IfStatsOutForwDatagrams",
                ["1.3.6.1.2.1.55.1.6.1.11"] = "ipv6IfStatsOutRequests",
                ["1.3.6.1.2.1.55.1.6.1.12"] = "ipv6IfStatsOutDiscards",
                ["1.3.6.1.2.1.55.1.6.1.13"] = "ipv6IfStatsOutFragOKs",
                ["1.3.6.1.2.1.55.1.6.1.14"] = "ipv6IfStatsOutFragFails",
                ["1.3.6.1.2.1.55.1.6.1.15"] = "ipv6IfStatsOutFragCreates",
                ["1.3.6.1.2.1.55.1.6.1.16"] = "ipv6IfStatsReasmReqds",
                ["1.3.6.1.2.1.55.1.6.1.17"] = "ipv6IfStatsReasmOKs",
                ["1.3.6.1.2.1.55.1.6.1.18"] = "ipv6IfStatsReasmFails",
                ["1.3.6.1.2.1.55.1.6.1.19"] = "ipv6IfStatsInMcastPkts",
                ["1.3.6.1.2.1.55.1.6.1.20"] = "ipv6IfStatsOutMcastPkts",
                ["1.3.6.1.2.1.55.1.7"] = "ipv6AddrPrefixTable",
                ["1.3.6.1.2.1.55.1.7.1"] = "ipv6AddrPrefixEntry",
                ["1.3.6.1.2.1.55.1.7.1.1"] = "ipv6AddrPrefix",
                ["1.3.6.1.2.1.55.1.7.1.2"] = "ipv6AddrPrefixLength",
                ["1.3.6.1.2.1.55.1.7.1.3"] = "ipv6AddrPrefixOnLinkFlag",
                ["1.3.6.1.2.1.55.1.7.1.4"] = "ipv6AddrPrefixAutonomousFlag",
                ["1.3.6.1.2.1.55.1.7.1.5"] = "ipv6AddrPrefixAdvPreferredLifetime",
                ["1.3.6.1.2.1.55.1.7.1.6"] = "ipv6AddrPrefixAdvValidLifetime",
                ["1.3.6.1.2.1.55.1.8"] = "ipv6AddrTable",
                ["1.3.6.1.2.1.55.1.8.1"] = "ipv6AddrEntry",
                ["1.3.6.1.2.1.55.1.8.1.1"] = "ipv6AddrAddress",
                ["1.3.6.1.2.1.55.1.8.1.2"] = "ipv6AddrPfxLength",
                ["1.3.6.1.2.1.55.1.8.1.3"] = "ipv6AddrType",
                ["1.3.6.1.2.1.55.1.8.1.4"] = "ipv6AddrAnycastFlag",
                ["1.3.6.1.2.1.55.1.8.1.5"] = "ipv6AddrStatus",
                ["1.3.6.1.2.1.55.1.9"] = "ipv6RouteNumber",
                ["1.3.6.1.2.1.55.1.10"] = "ipv6DiscardedRoutes",
                ["1.3.6.1.2.1.55.1.11"] = "ipv6RouteTable",
                ["1.3.6.1.2.1.55.1.11.1"] = "ipv6RouteEntry",
                ["1.3.6.1.2.1.55.1.11.1.1"] = "ipv6RouteDest",
                ["1.3.6.1.2.1.55.1.11.1.2"] = "ipv6RoutePfxLength",
                ["1.3.6.1.2.1.55.1.11.1.3"] = "ipv6RouteIndex",
                ["1.3.6.1.2.1.55.1.11.1.4"] = "ipv6RouteIfIndex",
                ["1.3.6.1.2.1.55.1.11.1.5"] = "ipv6RouteNextHop",
                ["1.3.6.1.2.1.55.1.11.1.6"] = "ipv6RouteType",
                ["1.3.6.1.2.1.55.1.11.1.7"] = "ipv6RouteProtocol",
                ["1.3.6.1.2.1.55.1.11.1.8"] = "ipv6RoutePolicy",
                ["1.3.6.1.2.1.55.1.11.1.9"] = "ipv6RouteAge",
                ["1.3.6.1.2.1.55.1.11.1.10"] = "ipv6RouteNextHopRDI",
                ["1.3.6.1.2.1.55.1.11.1.11"] = "ipv6RouteMetric",
                ["1.3.6.1.2.1.55.1.11.1.12"] = "ipv6RouteWeight",
                ["1.3.6.1.2.1.55.1.11.1.13"] = "ipv6RouteInfo",
                ["1.3.6.1.2.1.55.1.11.1.14"] = "ipv6RouteValid",
                ["1.3.6.1.2.1.55.1.12"] = "ipv6NetToMediaTable",
                ["1.3.6.1.2.1.55.1.12.1"] = "ipv6NetToMediaEntry",
                ["1.3.6.1.2.1.55.1.12.1.1"] = "ipv6NetToMediaNetAddress",
                ["1.3.6.1.2.1.55.1.12.1.2"] = "ipv6NetToMediaPhysAddress",
                ["1.3.6.1.2.1.55.1.12.1.3"] = "ipv6NetToMediaType",
                ["1.3.6.1.2.1.55.1.12.1.4"] = "ipv6IfNetToMediaState",
                ["1.3.6.1.2.1.55.1.12.1.5"] = "ipv6IfNetToMediaLastUpdated",
                ["1.3.6.1.2.1.55.1.12.1.6"] = "ipv6NetToMediaValid",
                ["1.3.6.1.2.1.55.2"] = "ipv6Notifications",
                ["1.3.6.1.2.1.55.2.0"] = "ipv6NotificationPrefix",
                ["1.3.6.1.2.1.55.2.0.1"] = "ipv6IfStateChange",
                ["1.3.6.1.2.1.55.3"] = "ipv6Conformance",
                ["1.3.6.1.2.1.55.3.1"] = "ipv6Compliances",
                ["1.3.6.1.2.1.55.3.1.1"] = "ipv6Compliance",
                ["1.3.6.1.2.1.55.3.2"] = "ipv6Groups",
                ["1.3.6.1.2.1.55.3.2.1"] = "ipv6GeneralGroup",
                ["1.3.6.1.2.1.55.3.2.2"] = "ipv6NotificationGroup",
                ["1.3.6.1.2.1.56"] = "ipv6IcmpMIB",
                ["1.3.6.1.2.1.56.1"] = "ipv6IcmpMIBObjects",
                ["1.3.6.1.2.1.56.1.1"] = "ipv6IfIcmpTable",
                ["1.3.6.1.2.1.56.1.1.1"] = "ipv6IfIcmpEntry",
                ["1.3.6.1.2.1.56.1.1.1.1"] = "ipv6IfIcmpInMsgs",
                ["1.3.6.1.2.1.56.1.1.1.2"] = "ipv6IfIcmpInErrors",
                ["1.3.6.1.2.1.56.1.1.1.3"] = "ipv6IfIcmpInDestUnreachs",
                ["1.3.6.1.2.1.56.1.1.1.4"] = "ipv6IfIcmpInAdminProhibs",
                ["1.3.6.1.2.1.56.1.1.1.5"] = "ipv6IfIcmpInTimeExcds",
                ["1.3.6.1.2.1.56.1.1.1.6"] = "ipv6IfIcmpInParmProblems",
                ["1.3.6.1.2.1.56.1.1.1.7"] = "ipv6IfIcmpInPktTooBigs",
                ["1.3.6.1.2.1.56.1.1.1.8"] = "ipv6IfIcmpInEchos",
                ["1.3.6.1.2.1.56.1.1.1.9"] = "ipv6IfIcmpInEchoReplies",
                ["1.3.6.1.2.1.56.1.1.1.10"] = "ipv6IfIcmpInRouterSolicits",
                ["1.3.6.1.2.1.56.1.1.1.11"] = "ipv6IfIcmpInRouterAdvertisements",
                ["1.3.6.1.2.1.56.1.1.1.12"] = "ipv6IfIcmpInNeighborSolicits",
                ["1.3.6.1.2.1.56.1.1.1.13"] = "ipv6IfIcmpInNeighborAdvertisements",
                ["1.3.6.1.2.1.56.1.1.1.14"] = "ipv6IfIcmpInRedirects",
                ["1.3.6.1.2.1.56.1.1.1.15"] = "ipv6IfIcmpInGroupMembQueries",
                ["1.3.6.1.2.1.56.1.1.1.16"] = "ipv6IfIcmpInGroupMembResponses",
                ["1.3.6.1.2.1.56.1.1.1.17"] = "ipv6IfIcmpInGroupMembReductions",
                ["1.3.6.1.2.1.56.1.1.1.18"] = "ipv6IfIcmpOutMsgs",
                ["1.3.6.1.2.1.56.1.1.1.19"] = "ipv6IfIcmpOutErrors",
                ["1.3.6.1.2.1.56.1.1.1.20"] = "ipv6IfIcmpOutDestUnreachs",
                ["1.3.6.1.2.1.56.1.1.1.21"] = "ipv6IfIcmpOutAdminProhibs",
                ["1.3.6.1.2.1.56.1.1.1.22"] = "ipv6IfIcmpOutTimeExcds",
                ["1.3.6.1.2.1.56.1.1.1.23"] = "ipv6IfIcmpOutParmProblems",
                ["1.3.6.1.2.1.56.1.1.1.24"] = "ipv6IfIcmpOutPktTooBigs",
                ["1.3.6.1.2.1.56.1.1.1.25"] = "ipv6IfIcmpOutEchos",
                ["1.3.6.1.2.1.56.1.1.1.26"] = "ipv6IfIcmpOutEchoReplies",
                ["1.3.6.1.2.1.56.1.1.1.27"] = "ipv6IfIcmpOutRouterSolicits",
                ["1.3.6.1.2.1.56.1.1.1.28"] = "ipv6IfIcmpOutRouterAdvertisements",
                ["1.3.6.1.2.1.56.1.1.1.29"] = "ipv6IfIcmpOutNeighborSolicits",
                ["1.3.6.1.2.1.56.1.1.1.30"] = "ipv6IfIcmpOutNeighborAdvertisements",
                ["1.3.6.1.2.1.56.1.1.1.31"] = "ipv6IfIcmpOutRedirects",
                ["1.3.6.1.2.1.56.1.1.1.32"] = "ipv6IfIcmpOutGroupMembQueries",
                ["1.3.6.1.2.1.56.1.1.1.33"] = "ipv6IfIcmpOutGroupMembResponses",
                ["1.3.6.1.2.1.56.1.1.1.34"] = "ipv6IfIcmpOutGroupMembReductions",
                ["1.3.6.1.2.1.56.2"] = "ipv6IcmpConformance",
                ["1.3.6.1.2.1.56.2.1"] = "ipv6IcmpCompliances",
                ["1.3.6.1.2.1.56.2.1.1"] = "ipv6IcmpCompliance",
                ["1.3.6.1.2.1.56.2.2"] = "ipv6IcmpGroups",
                ["1.3.6.1.2.1.56.2.2.1"] = "ipv6IcmpGroup",
                ["1.3.6.1.2.1.63"] = "schedMIB",
                ["1.3.6.1.2.1.63.1"] = "schedObjects",
                ["1.3.6.1.2.1.63.1.1"] = "schedLocalTime",
                ["1.3.6.1.2.1.63.1.2"] = "schedTable",
                ["1.3.6.1.2.1.63.1.2.1"] = "schedEntry",
                ["1.3.6.1.2.1.63.1.2.1.1"] = "schedOwner",
                ["1.3.6.1.2.1.63.1.2.1.2"] = "schedName",
                ["1.3.6.1.2.1.63.1.2.1.3"] = "schedDescr",
                ["1.3.6.1.2.1.63.1.2.1.4"] = "schedInterval",
                ["1.3.6.1.2.1.63.1.2.1.5"] = "schedWeekDay",
                ["1.3.6.1.2.1.63.1.2.1.6"] = "schedMonth",
                ["1.3.6.1.2.1.63.1.2.1.7"] = "schedDay",
                ["1.3.6.1.2.1.63.1.2.1.8"] = "schedHour",
                ["1.3.6.1.2.1.63.1.2.1.9"] = "schedMinute",
                ["1.3.6.1.2.1.63.1.2.1.10"] = "schedContextName",
                ["1.3.6.1.2.1.63.1.2.1.11"] = "schedVariable",
                ["1.3.6.1.2.1.63.1.2.1.12"] = "schedValue",
                ["1.3.6.1.2.1.63.1.2.1.13"] = "schedType",
                ["1.3.6.1.2.1.63.1.2.1.14"] = "schedAdminStatus",
                ["1.3.6.1.2.1.63.1.2.1.15"] = "schedOperStatus",
                ["1.3.6.1.2.1.63.1.2.1.16"] = "schedFailures",
                ["1.3.6.1.2.1.63.1.2.1.17"] = "schedLastFailure",
                ["1.3.6.1.2.1.63.1.2.1.18"] = "schedLastFailed",
                ["1.3.6.1.2.1.63.1.2.1.19"] = "schedStorageType",
                ["1.3.6.1.2.1.63.1.2.1.20"] = "schedRowStatus",
                ["1.3.6.1.2.1.63.1.2.1.21"] = "schedTriggers",
                ["1.3.6.1.2.1.63.2"] = "schedNotifications",
                ["1.3.6.1.2.1.63.2.0"] = "schedTraps",
                ["1.3.6.1.2.1.63.2.0.1"] = "schedActionFailure",
                ["1.3.6.1.2.1.63.3"] = "schedConformance",
                ["1.3.6.1.2.1.63.3.1"] = "schedCompliances",
                ["1.3.6.1.2.1.63.3.1.1"] = "schedCompliance",
                ["1.3.6.1.2.1.63.3.1.2"] = "schedCompliance2",
                ["1.3.6.1.2.1.63.3.2"] = "schedGroups",
                ["1.3.6.1.2.1.63.3.2.1"] = "schedGroup",
                ["1.3.6.1.2.1.63.3.2.2"] = "schedCalendarGroup",
                ["1.3.6.1.2.1.63.3.2.3"] = "schedNotificationsGroup",
                ["1.3.6.1.2.1.63.3.2.4"] = "schedGroup2",
                ["1.3.6.1.2.1.76"] = "inetAddressMIB",
                ["1.3.6.1.2.1.88"] = "dismanEventMIB",
                ["1.3.6.1.2.1.88.1"] = "dismanEventMIBObjects",
                ["1.3.6.1.2.1.88.1.1"] = "mteResource",
                ["1.3.6.1.2.1.88.1.1.1"] = "mteResourceSampleMinimum",
                ["1.3.6.1.2.1.88.1.1.2"] = "mteResourceSampleInstanceMaximum",
                ["1.3.6.1.2.1.88.1.1.3"] = "mteResourceSampleInstances",
                ["1.3.6.1.2.1.88.1.1.4"] = "mteResourceSampleInstancesHigh",
                ["1.3.6.1.2.1.88.1.1.5"] = "mteResourceSampleInstanceLacks",
                ["1.3.6.1.2.1.88.1.2"] = "mteTrigger",
                ["1.3.6.1.2.1.88.1.2.1"] = "mteTriggerFailures",
                ["1.3.6.1.2.1.88.1.2.2"] = "mteTriggerTable",
                ["1.3.6.1.2.1.88.1.2.2.1"] = "mteTriggerEntry",
                ["1.3.6.1.2.1.88.1.2.2.1.1"] = "mteOwner",
                ["1.3.6.1.2.1.88.1.2.2.1.2"] = "mteTriggerName",
                ["1.3.6.1.2.1.88.1.2.2.1.3"] = "mteTriggerComment",
                ["1.3.6.1.2.1.88.1.2.2.1.4"] = "mteTriggerTest",
                ["1.3.6.1.2.1.88.1.2.2.1.5"] = "mteTriggerSampleType",
                ["1.3.6.1.2.1.88.1.2.2.1.6"] = "mteTriggerValueID",
                ["1.3.6.1.2.1.88.1.2.2.1.7"] = "mteTriggerValueIDWildcard",
                ["1.3.6.1.2.1.88.1.2.2.1.8"] = "mteTriggerTargetTag",
                ["1.3.6.1.2.1.88.1.2.2.1.9"] = "mteTriggerContextName",
                ["1.3.6.1.2.1.88.1.2.2.1.10"] = "mteTriggerContextNameWildcard",
                ["1.3.6.1.2.1.88.1.2.2.1.11"] = "mteTriggerFrequency",
                ["1.3.6.1.2.1.88.1.2.2.1.12"] = "mteTriggerObjectsOwner",
                ["1.3.6.1.2.1.88.1.2.2.1.13"] = "mteTriggerObjects",
                ["1.3.6.1.2.1.88.1.2.2.1.14"] = "mteTriggerEnabled",
                ["1.3.6.1.2.1.88.1.2.2.1.15"] = "mteTriggerEntryStatus",
                ["1.3.6.1.2.1.88.1.2.3"] = "mteTriggerDeltaTable",
                ["1.3.6.1.2.1.88.1.2.3.1"] = "mteTriggerDeltaEntry",
                ["1.3.6.1.2.1.88.1.2.3.1.1"] = "mteTriggerDeltaDiscontinuityID",
                ["1.3.6.1.2.1.88.1.2.3.1.2"] = "mteTriggerDeltaDiscontinuityIDWildcard",
                ["1.3.6.1.2.1.88.1.2.3.1.3"] = "mteTriggerDeltaDiscontinuityIDType",
                ["1.3.6.1.2.1.88.1.2.4"] = "mteTriggerExistenceTable",
                ["1.3.6.1.2.1.88.1.2.4.1"] = "mteTriggerExistenceEntry",
                ["1.3.6.1.2.1.88.1.2.4.1.1"] = "mteTriggerExistenceTest",
                ["1.3.6.1.2.1.88.1.2.4.1.2"] = "mteTriggerExistenceStartup",
                ["1.3.6.1.2.1.88.1.2.4.1.3"] = "mteTriggerExistenceObjectsOwner",
                ["1.3.6.1.2.1.88.1.2.4.1.4"] = "mteTriggerExistenceObjects",
                ["1.3.6.1.2.1.88.1.2.4.1.5"] = "mteTriggerExistenceEventOwner",
                ["1.3.6.1.2.1.88.1.2.4.1.6"] = "mteTriggerExistenceEvent",
                ["1.3.6.1.2.1.88.1.2.5"] = "mteTriggerBooleanTable",
                ["1.3.6.1.2.1.88.1.2.5.1"] = "mteTriggerBooleanEntry",
                ["1.3.6.1.2.1.88.1.2.5.1.1"] = "mteTriggerBooleanComparison",
                ["1.3.6.1.2.1.88.1.2.5.1.2"] = "mteTriggerBooleanValue",
                ["1.3.6.1.2.1.88.1.2.5.1.3"] = "mteTriggerBooleanStartup",
                ["1.3.6.1.2.1.88.1.2.5.1.4"] = "mteTriggerBooleanObjectsOwner",
                ["1.3.6.1.2.1.88.1.2.5.1.5"] = "mteTriggerBooleanObjects",
                ["1.3.6.1.2.1.88.1.2.5.1.6"] = "mteTriggerBooleanEventOwner",
                ["1.3.6.1.2.1.88.1.2.5.1.7"] = "mteTriggerBooleanEvent",
                ["1.3.6.1.2.1.88.1.2.6"] = "mteTriggerThresholdTable",
                ["1.3.6.1.2.1.88.1.2.6.1"] = "mteTriggerThresholdEntry",
                ["1.3.6.1.2.1.88.1.2.6.1.1"] = "mteTriggerThresholdStartup",
                ["1.3.6.1.2.1.88.1.2.6.1.2"] = "mteTriggerThresholdRising",
                ["1.3.6.1.2.1.88.1.2.6.1.3"] = "mteTriggerThresholdFalling",
                ["1.3.6.1.2.1.88.1.2.6.1.4"] = "mteTriggerThresholdDeltaRising",
                ["1.3.6.1.2.1.88.1.2.6.1.5"] = "mteTriggerThresholdDeltaFalling",
                ["1.3.6.1.2.1.88.1.2.6.1.6"] = "mteTriggerThresholdObjectsOwner",
                ["1.3.6.1.2.1.88.1.2.6.1.7"] = "mteTriggerThresholdObjects",
                ["1.3.6.1.2.1.88.1.2.6.1.8"] = "mteTriggerThresholdRisingEventOwner",
                ["1.3.6.1.2.1.88.1.2.6.1.9"] = "mteTriggerThresholdRisingEvent",
                ["1.3.6.1.2.1.88.1.2.6.1.10"] = "mteTriggerThresholdFallingEventOwner",
                ["1.3.6.1.2.1.88.1.2.6.1.11"] = "mteTriggerThresholdFallingEvent",
                ["1.3.6.1.2.1.88.1.2.6.1.12"] = "mteTriggerThresholdDeltaRisingEventOwner",
                ["1.3.6.1.2.1.88.1.2.6.1.13"] = "mteTriggerThresholdDeltaRisingEvent",
                ["1.3.6.1.2.1.88.1.2.6.1.14"] = "mteTriggerThresholdDeltaFallingEventOwner",
                ["1.3.6.1.2.1.88.1.2.6.1.15"] = "mteTriggerThresholdDeltaFallingEvent",
                ["1.3.6.1.2.1.88.1.3"] = "mteObjects",
                ["1.3.6.1.2.1.88.1.3.1"] = "mteObjectsTable",
                ["1.3.6.1.2.1.88.1.3.1.1"] = "mteObjectsEntry",
                ["1.3.6.1.2.1.88.1.3.1.1.1"] = "mteObjectsName",
                ["1.3.6.1.2.1.88.1.3.1.1.2"] = "mteObjectsIndex",
                ["1.3.6.1.2.1.88.1.3.1.1.3"] = "mteObjectsID",
                ["1.3.6.1.2.1.88.1.3.1.1.4"] = "mteObjectsIDWildcard",
                ["1.3.6.1.2.1.88.1.3.1.1.5"] = "mteObjectsEntryStatus",
                ["1.3.6.1.2.1.88.1.4"] = "mteEvent",
                ["1.3.6.1.2.1.88.1.4.1"] = "mteEventFailures",
                ["1.3.6.1.2.1.88.1.4.2"] = "mteEventTable",
                ["1.3.6.1.2.1.88.1.4.2.1"] = "mteEventEntry",
                ["1.3.6.1.2.1.88.1.4.2.1.1"] = "mteEventName",
                ["1.3.6.1.2.1.88.1.4.2.1.2"] = "mteEventComment",
                ["1.3.6.1.2.1.88.1.4.2.1.3"] = "mteEventActions",
                ["1.3.6.1.2.1.88.1.4.2.1.4"] = "mteEventEnabled",
                ["1.3.6.1.2.1.88.1.4.2.1.5"] = "mteEventEntryStatus",
                ["1.3.6.1.2.1.88.1.4.3"] = "mteEventNotificationTable",
                ["1.3.6.1.2.1.88.1.4.3.1"] = "mteEventNotificationEntry",
                ["1.3.6.1.2.1.88.1.4.3.1.1"] = "mteEventNotification",
                ["1.3.6.1.2.1.88.1.4.3.1.2"] = "mteEventNotificationObjectsOwner",
                ["1.3.6.1.2.1.88.1.4.3.1.3"] = "mteEventNotificationObjects",
                ["1.3.6.1.2.1.88.1.4.4"] = "mteEventSetTable",
                ["1.3.6.1.2.1.88.1.4.4.1"] = "mteEventSetEntry",
                ["1.3.6.1.2.1.88.1.4.4.1.1"] = "mteEventSetObject",
                ["1.3.6.1.2.1.88.1.4.4.1.2"] = "mteEventSetObjectWildcard",
                ["1.3.6.1.2.1.88.1.4.4.1.3"] = "mteEventSetValue",
                ["1.3.6.1.2.1.88.1.4.4.1.4"] = "mteEventSetTargetTag",
                ["1.3.6.1.2.1.88.1.4.4.1.5"] = "mteEventSetContextName",
                ["1.3.6.1.2.1.88.1.4.4.1.6"] = "mteEventSetContextNameWildcard",
                ["1.3.6.1.2.1.88.2"] = "dismanEventMIBNotificationPrefix",
                ["1.3.6.1.2.1.88.2.0"] = "dismanEventMIBNotifications",
                ["1.3.6.1.2.1.88.2.0.1"] = "mteTriggerFired",
                ["1.3.6.1.2.1.88.2.0.2"] = "mteTriggerRising",
                ["1.3.6.1.2.1.88.2.0.3"] = "mteTriggerFalling",
                ["1.3.6.1.2.1.88.2.0.4"] = "mteTriggerFailure",
                ["1.3.6.1.2.1.88.2.0.5"] = "mteEventSetFailure",
                ["1.3.6.1.2.1.88.2.1"] = "dismanEventMIBNotificationObjects",
                ["1.3.6.1.2.1.88.2.1.1"] = "mteHotTrigger",
                ["1.3.6.1.2.1.88.2.1.2"] = "mteHotTargetName",
                ["1.3.6.1.2.1.88.2.1.3"] = "mteHotContextName",
                ["1.3.6.1.2.1.88.2.1.4"] = "mteHotOID",
                ["1.3.6.1.2.1.88.2.1.5"] = "mteHotValue",
                ["1.3.6.1.2.1.88.2.1.6"] = "mteFailedReason",
                ["1.3.6.1.2.1.88.3"] = "dismanEventMIBConformance",
                ["1.3.6.1.2.1.88.3.1"] = "dismanEventMIBCompliances",
                ["1.3.6.1.2.1.88.3.1.1"] = "dismanEventMIBCompliance",
                ["1.3.6.1.2.1.88.3.2"] = "dismanEventMIBGroups",
                ["1.3.6.1.2.1.88.3.2.1"] = "dismanEventResourceGroup",
                ["1.3.6.1.2.1.88.3.2.2"] = "dismanEventTriggerGroup",
                ["1.3.6.1.2.1.88.3.2.3"] = "dismanEventObjectsGroup",
                ["1.3.6.1.2.1.88.3.2.4"] = "dismanEventEventGroup",
                ["1.3.6.1.2.1.88.3.2.5"] = "dismanEventNotificationObjectGroup",
                ["1.3.6.1.2.1.88.3.2.6"] = "dismanEventNotificationGroup",
                ["1.3.6.1.2.1.92"] = "notificationLogMIB",
                ["1.3.6.1.2.1.92.1"] = "notificationLogMIBObjects",
                ["1.3.6.1.2.1.92.1.1"] = "nlmConfig",
                ["1.3.6.1.2.1.92.1.1.1"] = "nlmConfigGlobalEntryLimit",
                ["1.3.6.1.2.1.92.1.1.2"] = "nlmConfigGlobalAgeOut",
                ["1.3.6.1.2.1.92.1.1.3"] = "nlmConfigLogTable",
                ["1.3.6.1.2.1.92.1.1.3.1"] = "nlmConfigLogEntry",
                ["1.3.6.1.2.1.92.1.1.3.1.1"] = "nlmLogName",
                ["1.3.6.1.2.1.92.1.1.3.1.2"] = "nlmConfigLogFilterName",
                ["1.3.6.1.2.1.92.1.1.3.1.3"] = "nlmConfigLogEntryLimit",
                ["1.3.6.1.2.1.92.1.1.3.1.4"] = "nlmConfigLogAdminStatus",
                ["1.3.6.1.2.1.92.1.1.3.1.5"] = "nlmConfigLogOperStatus",
                ["1.3.6.1.2.1.92.1.1.3.1.6"] = "nlmConfigLogStorageType",
                ["1.3.6.1.2.1.92.1.1.3.1.7"] = "nlmConfigLogEntryStatus",
                ["1.3.6.1.2.1.92.1.2"] = "nlmStats",
                ["1.3.6.1.2.1.92.1.2.1"] = "nlmStatsGlobalNotificationsLogged",
                ["1.3.6.1.2.1.92.1.2.2"] = "nlmStatsGlobalNotificationsBumped",
                ["1.3.6.1.2.1.92.1.2.3"] = "nlmStatsLogTable",
                ["1.3.6.1.2.1.92.1.2.3.1"] = "nlmStatsLogEntry",
                ["1.3.6.1.2.1.92.1.2.3.1.1"] = "nlmStatsLogNotificationsLogged",
                ["1.3.6.1.2.1.92.1.2.3.1.2"] = "nlmStatsLogNotificationsBumped",
                ["1.3.6.1.2.1.92.1.3"] = "nlmLog",
                ["1.3.6.1.2.1.92.1.3.1"] = "nlmLogTable",
                ["1.3.6.1.2.1.92.1.3.1.1"] = "nlmLogEntry",
                ["1.3.6.1.2.1.92.1.3.1.1.1"] = "nlmLogIndex",
                ["1.3.6.1.2.1.92.1.3.1.1.2"] = "nlmLogTime",
                ["1.3.6.1.2.1.92.1.3.1.1.3"] = "nlmLogDateAndTime",
                ["1.3.6.1.2.1.92.1.3.1.1.4"] = "nlmLogEngineID",
                ["1.3.6.1.2.1.92.1.3.1.1.5"] = "nlmLogEngineTAddress",
                ["1.3.6.1.2.1.92.1.3.1.1.6"] = "nlmLogEngineTDomain",
                ["1.3.6.1.2.1.92.1.3.1.1.7"] = "nlmLogContextEngineID",
                ["1.3.6.1.2.1.92.1.3.1.1.8"] = "nlmLogContextName",
                ["1.3.6.1.2.1.92.1.3.1.1.9"] = "nlmLogNotificationID",
                ["1.3.6.1.2.1.92.1.3.2"] = "nlmLogVariableTable",
                ["1.3.6.1.2.1.92.1.3.2.1"] = "nlmLogVariableEntry",
                ["1.3.6.1.2.1.92.1.3.2.1.1"] = "nlmLogVariableIndex",
                ["1.3.6.1.2.1.92.1.3.2.1.2"] = "nlmLogVariableID",
                ["1.3.6.1.2.1.92.1.3.2.1.3"] = "nlmLogVariableValueType",
                ["1.3.6.1.2.1.92.1.3.2.1.4"] = "nlmLogVariableCounter32Val",
                ["1.3.6.1.2.1.92.1.3.2.1.5"] = "nlmLogVariableUnsigned32Val",
                ["1.3.6.1.2.1.92.1.3.2.1.6"] = "nlmLogVariableTimeTicksVal",
                ["1.3.6.1.2.1.92.1.3.2.1.7"] = "nlmLogVariableInteger32Val",
                ["1.3.6.1.2.1.92.1.3.2.1.8"] = "nlmLogVariableOctetStringVal",
                ["1.3.6.1.2.1.92.1.3.2.1.9"] = "nlmLogVariableIpAddressVal",
                ["1.3.6.1.2.1.92.1.3.2.1.10"] = "nlmLogVariableOidVal",
                ["1.3.6.1.2.1.92.1.3.2.1.11"] = "nlmLogVariableCounter64Val",
                ["1.3.6.1.2.1.92.1.3.2.1.12"] = "nlmLogVariableOpaqueVal",
                ["1.3.6.1.2.1.92.3"] = "notificationLogMIBConformance",
                ["1.3.6.1.2.1.92.3.1"] = "notificationLogMIBCompliances",
                ["1.3.6.1.2.1.92.3.1.1"] = "notificationLogMIBCompliance",
                ["1.3.6.1.2.1.92.3.2"] = "notificationLogMIBGroups",
                ["1.3.6.1.2.1.92.3.2.1"] = "notificationLogConfigGroup",
                ["1.3.6.1.2.1.92.3.2.2"] = "notificationLogStatsGroup",
                ["1.3.6.1.2.1.92.3.2.3"] = "notificationLogLogGroup",
                ["1.3.6.1.2.1.92.3.2.4"] = "notificationLogDateGroup",
                ["1.3.6.1.3"] = "experimental",
                ["1.3.6.1.3.86"] = "ipv6TcpMIB",
                ["1.3.6.1.3.86.2"] = "ipv6TcpConformance",
                ["1.3.6.1.3.86.2.1"] = "ipv6TcpCompliances",
                ["1.3.6.1.3.86.2.1.1"] = "ipv6TcpCompliance",
                ["1.3.6.1.3.86.2.2"] = "ipv6TcpGroups",
                ["1.3.6.1.3.86.2.2.1"] = "ipv6TcpGroup",
                ["1.3.6.1.3.87"] = "ipv6UdpMIB",
                ["1.3.6.1.3.87.2"] = "ipv6UdpConformance",
                ["1.3.6.1.3.87.2.1"] = "ipv6UdpCompliances",
                ["1.3.6.1.3.87.2.1.1"] = "ipv6UdpCompliance",
                ["1.3.6.1.3.87.2.2"] = "ipv6UdpGroups",
                ["1.3.6.1.3.87.2.2.1"] = "ipv6UdpGroup",
                ["1.3.6.1.4"] = "private",
                ["1.3.6.1.4.1"] = "enterprises",
                ["1.3.6.1.4.1.2021"] = "ucdavis",
                ["1.3.6.1.4.1.2021.2"] = "prTable",
                ["1.3.6.1.4.1.2021.2.1"] = "prEntry",
                ["1.3.6.1.4.1.2021.2.1.1"] = "prIndex",
                ["1.3.6.1.4.1.2021.2.1.2"] = "prNames",
                ["1.3.6.1.4.1.2021.2.1.3"] = "prMin",
                ["1.3.6.1.4.1.2021.2.1.4"] = "prMax",
                ["1.3.6.1.4.1.2021.2.1.5"] = "prCount",
                ["1.3.6.1.4.1.2021.2.1.100"] = "prErrorFlag",
                ["1.3.6.1.4.1.2021.2.1.101"] = "prErrMessage",
                ["1.3.6.1.4.1.2021.2.1.102"] = "prErrFix",
                ["1.3.6.1.4.1.2021.2.1.103"] = "prErrFixCmd",
                ["1.3.6.1.4.1.2021.4"] = "memory",
                ["1.3.6.1.4.1.2021.4.1"] = "memIndex",
                ["1.3.6.1.4.1.2021.4.2"] = "memErrorName",
                ["1.3.6.1.4.1.2021.4.3"] = "memTotalSwap",
                ["1.3.6.1.4.1.2021.4.4"] = "memAvailSwap",
                ["1.3.6.1.4.1.2021.4.5"] = "memTotalReal",
                ["1.3.6.1.4.1.2021.4.6"] = "memAvailReal",
                ["1.3.6.1.4.1.2021.4.7"] = "memTotalSwapTXT",
                ["1.3.6.1.4.1.2021.4.8"] = "memAvailSwapTXT",
                ["1.3.6.1.4.1.2021.4.9"] = "memTotalRealTXT",
                ["1.3.6.1.4.1.2021.4.10"] = "memAvailRealTXT",
                ["1.3.6.1.4.1.2021.4.11"] = "memTotalFree",
                ["1.3.6.1.4.1.2021.4.12"] = "memMinimumSwap",
                ["1.3.6.1.4.1.2021.4.13"] = "memShared",
                ["1.3.6.1.4.1.2021.4.14"] = "memBuffer",
                ["1.3.6.1.4.1.2021.4.15"] = "memCached",
                ["1.3.6.1.4.1.2021.4.16"] = "memUsedSwapTXT",
                ["1.3.6.1.4.1.2021.4.17"] = "memUsedRealTXT",
                ["1.3.6.1.4.1.2021.4.100"] = "memSwapError",
                ["1.3.6.1.4.1.2021.4.101"] = "memSwapErrorMsg",
                ["1.3.6.1.4.1.2021.8"] = "extTable",
                ["1.3.6.1.4.1.2021.8.1"] = "extEntry",
                ["1.3.6.1.4.1.2021.8.1.1"] = "extIndex",
                ["1.3.6.1.4.1.2021.8.1.2"] = "extNames",
                ["1.3.6.1.4.1.2021.8.1.3"] = "extCommand",
                ["1.3.6.1.4.1.2021.8.1.100"] = "extResult",
                ["1.3.6.1.4.1.2021.8.1.101"] = "extOutput",
                ["1.3.6.1.4.1.2021.8.1.102"] = "extErrFix",
                ["1.3.6.1.4.1.2021.8.1.103"] = "extErrFixCmd",
                ["1.3.6.1.4.1.2021.9"] = "dskTable",
                ["1.3.6.1.4.1.2021.9.1"] = "dskEntry",
                ["1.3.6.1.4.1.2021.9.1.1"] = "dskIndex",
                ["1.3.6.1.4.1.2021.9.1.2"] = "dskPath",
                ["1.3.6.1.4.1.2021.9.1.3"] = "dskDevice",
                ["1.3.6.1.4.1.2021.9.1.4"] = "dskMinimum",
                ["1.3.6.1.4.1.2021.9.1.5"] = "dskMinPercent",
                ["1.3.6.1.4.1.2021.9.1.6"] = "dskTotal",
                ["1.3.6.1.4.1.2021.9.1.7"] = "dskAvail",
                ["1.3.6.1.4.1.2021.9.1.8"] = "dskUsed",
                ["1.3.6.1.4.1.2021.9.1.9"] = "dskPercent",
                ["1.3.6.1.4.1.2021.9.1.10"] = "dskPercentNode",
                ["1.3.6.1.4.1.2021.9.1.11"] = "dskTotalLow",
                ["1.3.6.1.4.1.2021.9.1.12"] = "dskTotalHigh",
                ["1.3.6.1.4.1.2021.9.1.13"] = "dskAvailLow",
                ["1.3.6.1.4.1.2021.9.1.14"] = "dskAvailHigh",
                ["1.3.6.1.4.1.2021.9.1.15"] = "dskUsedLow",
                ["1.3.6.1.4.1.2021.9.1.16"] = "dskUsedHigh",
                ["1.3.6.1.4.1.2021.9.1.100"] = "dskErrorFlag",
                ["1.3.6.1.4.1.2021.9.1.101"] = "dskErrorMsg",
                ["1.3.6.1.4.1.2021.10"] = "laTable",
                ["1.3.6.1.4.1.2021.10.1"] = "laEntry",
                ["1.3.6.1.4.1.2021.10.1.1"] = "laIndex",
                ["1.3.6.1.4.1.2021.10.1.2"] = "laNames",
                ["1.3.6.1.4.1.2021.10.1.3"] = "laLoad",
                ["1.3.6.1.4.1.2021.10.1.4"] = "laConfig",
                ["1.3.6.1.4.1.2021.10.1.5"] = "laLoadInt",
                ["1.3.6.1.4.1.2021.10.1.6"] = "laLoadFloat",
                ["1.3.6.1.4.1.2021.10.1.100"] = "laErrorFlag",
                ["1.3.6.1.4.1.2021.10.1.101"] = "laErrMessage",
                ["1.3.6.1.4.1.2021.11"] = "systemStats",
                ["1.3.6.1.4.1.2021.11.1"] = "ssIndex",
                ["1.3.6.1.4.1.2021.11.2"] = "ssErrorName",
                ["1.3.6.1.4.1.2021.11.3"] = "ssSwapIn",
                ["1.3.6.1.4.1.2021.11.4"] = "ssSwapOut",
                ["1.3.6.1.4.1.2021.11.5"] = "ssIOSent",
                ["1.3.6.1.4.1.2021.11.6"] = "ssIOReceive",
                ["1.3.6.1.4.1.2021.11.7"] = "ssSysInterrupts",
                ["1.3.6.1.4.1.2021.11.8"] = "ssSysContext",
                ["1.3.6.1.4.1.2021.11.9"] = "ssCpuUser",
                ["1.3.6.1.4.1.2021.11.10"] = "ssCpuSystem",
                ["1.3.6.1.4.1.2021.11.11"] = "ssCpuIdle",
                ["1.3.6.1.4.1.2021.11.50"] = "ssCpuRawUser",
                ["1.3.6.1.4.1.2021.11.51"] = "ssCpuRawNice",
                ["1.3.6.1.4.1.2021.11.52"] = "ssCpuRawSystem",
                ["1.3.6.1.4.1.2021.11.53"] = "ssCpuRawIdle",
                ["1.3.6.1.4.1.2021.11.54"] = "ssCpuRawWait",
                ["1.3.6.1.4.1.2021.11.55"] = "ssCpuRawKernel",
                ["1.3.6.1.4.1.2021.11.56"] = "ssCpuRawInterrupt",
                ["1.3.6.1.4.1.2021.11.57"] = "ssIORawSent",
                ["1.3.6.1.4.1.2021.11.58"] = "ssIORawReceived",
                ["1.3.6.1.4.1.2021.11.59"] = "ssRawInterrupts",
                ["1.3.6.1.4.1.2021.11.60"] = "ssRawContexts",
                ["1.3.6.1.4.1.2021.11.61"] = "ssCpuRawSoftIRQ",
                ["1.3.6.1.4.1.2021.11.62"] = "ssRawSwapIn",
                ["1.3.6.1.4.1.2021.11.63"] = "ssRawSwapOut",
                ["1.3.6.1.4.1.2021.12"] = "ucdInternal",
                ["1.3.6.1.4.1.2021.13"] = "ucdExperimental",
                ["1.3.6.1.4.1.2021.13.14"] = "ucdDlmodMIB",
                ["1.3.6.1.4.1.2021.13.14.1"] = "dlmodNextIndex",
                ["1.3.6.1.4.1.2021.13.14.2"] = "dlmodTable",
                ["1.3.6.1.4.1.2021.13.14.2.1"] = "dlmodEntry",
                ["1.3.6.1.4.1.2021.13.14.2.1.1"] = "dlmodIndex",
                ["1.3.6.1.4.1.2021.13.14.2.1.2"] = "dlmodName",
                ["1.3.6.1.4.1.2021.13.14.2.1.3"] = "dlmodPath",
                ["1.3.6.1.4.1.2021.13.14.2.1.4"] = "dlmodError",
                ["1.3.6.1.4.1.2021.13.14.2.1.5"] = "dlmodStatus",
                ["1.3.6.1.4.1.2021.13.15"] = "ucdDiskIOMIB",
                ["1.3.6.1.4.1.2021.13.15.1"] = "diskIOTable",
                ["1.3.6.1.4.1.2021.13.15.1.1"] = "diskIOEntry",
                ["1.3.6.1.4.1.2021.13.15.1.1.1"] = "diskIOIndex",
                ["1.3.6.1.4.1.2021.13.15.1.1.2"] = "diskIODevice",
                ["1.3.6.1.4.1.2021.13.15.1.1.3"] = "diskIONRead",
                ["1.3.6.1.4.1.2021.13.15.1.1.4"] = "diskIONWritten",
                ["1.3.6.1.4.1.2021.13.15.1.1.5"] = "diskIOReads",
                ["1.3.6.1.4.1.2021.13.15.1.1.6"] = "diskIOWrites",
                ["1.3.6.1.4.1.2021.13.15.1.1.9"] = "diskIOLA1",
                ["1.3.6.1.4.1.2021.13.15.1.1.10"] = "diskIOLA5",
                ["1.3.6.1.4.1.2021.13.15.1.1.11"] = "diskIOLA15",
                ["1.3.6.1.4.1.2021.13.15.1.1.12"] = "diskIONReadX",
                ["1.3.6.1.4.1.2021.13.15.1.1.13"] = "diskIONWrittenX",
                ["1.3.6.1.4.1.2021.14"] = "ucdDemoMIB",
                ["1.3.6.1.4.1.2021.14.1"] = "ucdDemoMIBObjects",
                ["1.3.6.1.4.1.2021.14.1.1"] = "ucdDemoPublic",
                ["1.3.6.1.4.1.2021.14.1.1.1"] = "ucdDemoResetKeys",
                ["1.3.6.1.4.1.2021.14.1.1.2"] = "ucdDemoPublicString",
                ["1.3.6.1.4.1.2021.14.1.1.3"] = "ucdDemoUserList",
                ["1.3.6.1.4.1.2021.14.1.1.4"] = "ucdDemoPassphrase",
                ["1.3.6.1.4.1.2021.15"] = "fileTable",
                ["1.3.6.1.4.1.2021.15.1"] = "fileEntry",
                ["1.3.6.1.4.1.2021.15.1.1"] = "fileIndex",
                ["1.3.6.1.4.1.2021.15.1.2"] = "fileName",
                ["1.3.6.1.4.1.2021.15.1.3"] = "fileSize",
                ["1.3.6.1.4.1.2021.15.1.4"] = "fileMax",
                ["1.3.6.1.4.1.2021.15.1.100"] = "fileErrorFlag",
                ["1.3.6.1.4.1.2021.15.1.101"] = "fileErrorMsg",
                ["1.3.6.1.4.1.2021.16"] = "logMatch",
                ["1.3.6.1.4.1.2021.16.1"] = "logMatchMaxEntries",
                ["1.3.6.1.4.1.2021.16.2"] = "logMatchTable",
                ["1.3.6.1.4.1.2021.16.2.1"] = "logMatchEntry",
                ["1.3.6.1.4.1.2021.16.2.1.1"] = "logMatchIndex",
                ["1.3.6.1.4.1.2021.16.2.1.2"] = "logMatchName",
                ["1.3.6.1.4.1.2021.16.2.1.3"] = "logMatchFilename",
                ["1.3.6.1.4.1.2021.16.2.1.4"] = "logMatchRegEx",
                ["1.3.6.1.4.1.2021.16.2.1.5"] = "logMatchGlobalCounter",
                ["1.3.6.1.4.1.2021.16.2.1.6"] = "logMatchGlobalCount",
                ["1.3.6.1.4.1.2021.16.2.1.7"] = "logMatchCurrentCounter",
                ["1.3.6.1.4.1.2021.16.2.1.8"] = "logMatchCurrentCount",
                ["1.3.6.1.4.1.2021.16.2.1.9"] = "logMatchCounter",
                ["1.3.6.1.4.1.2021.16.2.1.10"] = "logMatchCount",
                ["1.3.6.1.4.1.2021.16.2.1.11"] = "logMatchCycle",
                ["1.3.6.1.4.1.2021.16.2.1.100"] = "logMatchErrorFlag",
                ["1.3.6.1.4.1.2021.16.2.1.101"] = "logMatchRegExCompilation",
                ["1.3.6.1.4.1.2021.100"] = "version",
                ["1.3.6.1.4.1.2021.100.1"] = "versionIndex",
                ["1.3.6.1.4.1.2021.100.2"] = "versionTag",
                ["1.3.6.1.4.1.2021.100.3"] = "versionDate",
                ["1.3.6.1.4.1.2021.100.4"] = "versionCDate",
                ["1.3.6.1.4.1.2021.100.5"] = "versionIdent",
                ["1.3.6.1.4.1.2021.100.6"] = "versionConfigureOptions",
                ["1.3.6.1.4.1.2021.100.10"] = "versionClearCache",
                ["1.3.6.1.4.1.2021.100.11"] = "versionUpdateConfig",
                ["1.3.6.1.4.1.2021.100.12"] = "versionRestartAgent",
                ["1.3.6.1.4.1.2021.100.13"] = "versionSavePersistentData",
                ["1.3.6.1.4.1.2021.100.20"] = "versionDoDebugging",
                ["1.3.6.1.4.1.2021.101"] = "snmperrs",
                ["1.3.6.1.4.1.2021.101.1"] = "snmperrIndex",
                ["1.3.6.1.4.1.2021.101.2"] = "snmperrNames",
                ["1.3.6.1.4.1.2021.101.100"] = "snmperrErrorFlag",
                ["1.3.6.1.4.1.2021.101.101"] = "snmperrErrMessage",
                ["1.3.6.1.4.1.2021.102"] = "mrTable",
                ["1.3.6.1.4.1.2021.102.1"] = "mrEntry",
                ["1.3.6.1.4.1.2021.102.1.1"] = "mrIndex",
                ["1.3.6.1.4.1.2021.102.1.2"] = "mrModuleName",
                ["1.3.6.1.4.1.2021.250"] = "ucdSnmpAgent",
                ["1.3.6.1.4.1.2021.250.1"] = "hpux9",
                ["1.3.6.1.4.1.2021.250.2"] = "sunos4",
                ["1.3.6.1.4.1.2021.250.3"] = "solaris",
                ["1.3.6.1.4.1.2021.250.4"] = "osf",
                ["1.3.6.1.4.1.2021.250.5"] = "ultrix",
                ["1.3.6.1.4.1.2021.250.6"] = "hpux10",
                ["1.3.6.1.4.1.2021.250.7"] = "netbsd1",
                ["1.3.6.1.4.1.2021.250.8"] = "freebsd",
                ["1.3.6.1.4.1.2021.250.9"] = "irix",
                ["1.3.6.1.4.1.2021.250.10"] = "linux",
                ["1.3.6.1.4.1.2021.250.11"] = "bsdi",
                ["1.3.6.1.4.1.2021.250.12"] = "openbsd",
                ["1.3.6.1.4.1.2021.250.13"] = "win32",
                ["1.3.6.1.4.1.2021.250.14"] = "hpux11",
                ["1.3.6.1.4.1.2021.250.255"] = "unknown",
                ["1.3.6.1.4.1.2021.251"] = "ucdTraps",
                ["1.3.6.1.4.1.2021.251.1"] = "ucdStart",
                ["1.3.6.1.4.1.2021.251.2"] = "ucdShutdown",
                ["1.3.6.1.4.1.8072"] = "netSnmp",
                ["1.3.6.1.4.1.8072.1"] = "netSnmpObjects",
                ["1.3.6.1.4.1.8072.1.1"] = "nsVersion",
                ["1.3.6.1.4.1.8072.1.2"] = "nsMibRegistry",
                ["1.3.6.1.4.1.8072.1.2.1"] = "nsModuleTable",
                ["1.3.6.1.4.1.8072.1.2.1.1"] = "nsModuleEntry",
                ["1.3.6.1.4.1.8072.1.2.1.1.1"] = "nsmContextName",
                ["1.3.6.1.4.1.8072.1.2.1.1.2"] = "nsmRegistrationPoint",
                ["1.3.6.1.4.1.8072.1.2.1.1.3"] = "nsmRegistrationPriority",
                ["1.3.6.1.4.1.8072.1.2.1.1.4"] = "nsModuleName",
                ["1.3.6.1.4.1.8072.1.2.1.1.5"] = "nsModuleModes",
                ["1.3.6.1.4.1.8072.1.2.1.1.6"] = "nsModuleTimeout",
                ["1.3.6.1.4.1.8072.1.3"] = "nsExtensions",
                ["1.3.6.1.4.1.8072.1.3.1"] = "netSnmpExtendMIB",
                ["1.3.6.1.4.1.8072.1.3.2"] = "nsExtendObjects",
                ["1.3.6.1.4.1.8072.1.3.2.1"] = "nsExtendNumEntries",
                ["1.3.6.1.4.1.8072.1.3.2.2"] = "nsExtendConfigTable",
                ["1.3.6.1.4.1.8072.1.3.2.2.1"] = "nsExtendConfigEntry",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.1"] = "nsExtendToken",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.2"] = "nsExtendCommand",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.3"] = "nsExtendArgs",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.4"] = "nsExtendInput",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.5"] = "nsExtendCacheTime",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.6"] = "nsExtendExecType",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.7"] = "nsExtendRunType",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.20"] = "nsExtendStorage",
                ["1.3.6.1.4.1.8072.1.3.2.2.1.21"] = "nsExtendStatus",
                ["1.3.6.1.4.1.8072.1.3.2.3"] = "nsExtendOutput1Table",
                ["1.3.6.1.4.1.8072.1.3.2.3.1"] = "nsExtendOutput1Entry",
                ["1.3.6.1.4.1.8072.1.3.2.3.1.1"] = "nsExtendOutput1Line",
                ["1.3.6.1.4.1.8072.1.3.2.3.1.2"] = "nsExtendOutputFull",
                ["1.3.6.1.4.1.8072.1.3.2.3.1.3"] = "nsExtendOutNumLines",
                ["1.3.6.1.4.1.8072.1.3.2.3.1.4"] = "nsExtendResult",
                ["1.3.6.1.4.1.8072.1.3.2.4"] = "nsExtendOutput2Table",
                ["1.3.6.1.4.1.8072.1.3.2.4.1"] = "nsExtendOutput2Entry",
                ["1.3.6.1.4.1.8072.1.3.2.4.1.1"] = "nsExtendLineIndex",
                ["1.3.6.1.4.1.8072.1.3.2.4.1.2"] = "nsExtendOutLine",
                ["1.3.6.1.4.1.8072.1.3.3"] = "nsExtendGroups",
                ["1.3.6.1.4.1.8072.1.3.3.1"] = "nsExtendConfigGroup",
                ["1.3.6.1.4.1.8072.1.3.3.2"] = "nsExtendOutputGroup",
                ["1.3.6.1.4.1.8072.1.4"] = "nsDLMod",
                ["1.3.6.1.4.1.8072.1.5"] = "nsCache",
                ["1.3.6.1.4.1.8072.1.5.1"] = "nsCacheDefaultTimeout",
                ["1.3.6.1.4.1.8072.1.5.2"] = "nsCacheEnabled",
                ["1.3.6.1.4.1.8072.1.5.3"] = "nsCacheTable",
                ["1.3.6.1.4.1.8072.1.5.3.1"] = "nsCacheEntry",
                ["1.3.6.1.4.1.8072.1.5.3.1.1"] = "nsCachedOID",
                ["1.3.6.1.4.1.8072.1.5.3.1.2"] = "nsCacheTimeout",
                ["1.3.6.1.4.1.8072.1.5.3.1.3"] = "nsCacheStatus",
                ["1.3.6.1.4.1.8072.1.6"] = "nsErrorHistory",
                ["1.3.6.1.4.1.8072.1.7"] = "nsConfiguration",
                ["1.3.6.1.4.1.8072.1.7.1"] = "nsConfigDebug",
                ["1.3.6.1.4.1.8072.1.7.1.1"] = "nsDebugEnabled",
                ["1.3.6.1.4.1.8072.1.7.1.2"] = "nsDebugOutputAll",
                ["1.3.6.1.4.1.8072.1.7.1.3"] = "nsDebugDumpPdu",
                ["1.3.6.1.4.1.8072.1.7.1.4"] = "nsDebugTokenTable",
                ["1.3.6.1.4.1.8072.1.7.1.4.1"] = "nsDebugTokenEntry",
                ["1.3.6.1.4.1.8072.1.7.1.4.1.2"] = "nsDebugTokenPrefix",
                ["1.3.6.1.4.1.8072.1.7.1.4.1.4"] = "nsDebugTokenStatus",
                ["1.3.6.1.4.1.8072.1.7.2"] = "nsConfigLogging",
                ["1.3.6.1.4.1.8072.1.7.2.1"] = "nsLoggingTable",
                ["1.3.6.1.4.1.8072.1.7.2.1.1"] = "nsLoggingEntry",
                ["1.3.6.1.4.1.8072.1.7.2.1.1.1"] = "nsLogLevel",
                ["1.3.6.1.4.1.8072.1.7.2.1.1.2"] = "nsLogToken",
                ["1.3.6.1.4.1.8072.1.7.2.1.1.3"] = "nsLogType",
                ["1.3.6.1.4.1.8072.1.7.2.1.1.4"] = "nsLogMaxLevel",
                ["1.3.6.1.4.1.8072.1.7.2.1.1.5"] = "nsLogStatus",
                ["1.3.6.1.4.1.8072.1.8"] = "nsTransactions",
                ["1.3.6.1.4.1.8072.1.8.1"] = "nsTransactionTable",
                ["1.3.6.1.4.1.8072.1.8.1.1"] = "nsTransactionEntry",
                ["1.3.6.1.4.1.8072.1.8.1.1.1"] = "nsTransactionID",
                ["1.3.6.1.4.1.8072.1.8.1.1.2"] = "nsTransactionMode",
                ["1.3.6.1.4.1.8072.1.9"] = "netSnmpVacmMIB",
                ["1.3.6.1.4.1.8072.1.9.1"] = "nsVacmAccessTable",
                ["1.3.6.1.4.1.8072.1.9.1.1"] = "nsVacmAccessEntry",
                ["1.3.6.1.4.1.8072.1.9.1.1.1"] = "nsVacmAuthType",
                ["1.3.6.1.4.1.8072.1.9.1.1.2"] = "nsVacmContextMatch",
                ["1.3.6.1.4.1.8072.1.9.1.1.3"] = "nsVacmViewName",
                ["1.3.6.1.4.1.8072.1.9.1.1.4"] = "nsVacmStorageType",
                ["1.3.6.1.4.1.8072.1.9.1.1.5"] = "nsVacmStatus",
                ["1.3.6.1.4.1.8072.2"] = "netSnmpExamples",
                ["1.3.6.1.4.1.8072.2.1"] = "netSnmpExampleScalars",
                ["1.3.6.1.4.1.8072.2.1.1"] = "netSnmpExampleInteger",
                ["1.3.6.1.4.1.8072.2.1.2"] = "netSnmpExampleSleeper",
                ["1.3.6.1.4.1.8072.2.1.3"] = "netSnmpExampleString",
                ["1.3.6.1.4.1.8072.2.2"] = "netSnmpExampleTables",
                ["1.3.6.1.4.1.8072.2.2.1"] = "netSnmpIETFWGTable",
                ["1.3.6.1.4.1.8072.2.2.1.1"] = "netSnmpIETFWGEntry",
                ["1.3.6.1.4.1.8072.2.2.1.1.1"] = "nsIETFWGName",
                ["1.3.6.1.4.1.8072.2.2.1.1.2"] = "nsIETFWGChair1",
                ["1.3.6.1.4.1.8072.2.2.1.1.3"] = "nsIETFWGChair2",
                ["1.3.6.1.4.1.8072.2.2.2"] = "netSnmpHostsTable",
                ["1.3.6.1.4.1.8072.2.2.2.1"] = "netSnmpHostsEntry",
                ["1.3.6.1.4.1.8072.2.2.2.1.1"] = "netSnmpHostName",
                ["1.3.6.1.4.1.8072.2.2.2.1.2"] = "netSnmpHostAddressType",
                ["1.3.6.1.4.1.8072.2.2.2.1.3"] = "netSnmpHostAddress",
                ["1.3.6.1.4.1.8072.2.2.2.1.4"] = "netSnmpHostStorage",
                ["1.3.6.1.4.1.8072.2.2.2.1.5"] = "netSnmpHostRowStatus",
                ["1.3.6.1.4.1.8072.2.3"] = "netSnmpExampleNotifications",
                ["1.3.6.1.4.1.8072.2.3.0"] = "netSnmpExampleNotificationPrefix",
                ["1.3.6.1.4.1.8072.2.3.0.1"] = "netSnmpExampleHeartbeatNotification",
                ["1.3.6.1.4.1.8072.2.3.1"] = "netSnmpExampleNotification",
                ["1.3.6.1.4.1.8072.2.3.2"] = "netSnmpExampleNotificationObjects",
                ["1.3.6.1.4.1.8072.2.3.2.1"] = "netSnmpExampleHeartbeatRate",
                ["1.3.6.1.4.1.8072.2.3.2.2"] = "netSnmpExampleHeartbeatName",
                ["1.3.6.1.4.1.8072.2.255"] = "netSnmpPassExamples",
                ["1.3.6.1.4.1.8072.2.255.1"] = "netSnmpPassString",
                ["1.3.6.1.4.1.8072.2.255.2"] = "netSnmpPassTable",
                ["1.3.6.1.4.1.8072.2.255.2.1"] = "netSnmpPassEntry",
                ["1.3.6.1.4.1.8072.2.255.2.1.1"] = "netSnmpPassIndex",
                ["1.3.6.1.4.1.8072.2.255.2.1.2"] = "netSnmpPassInteger",
                ["1.3.6.1.4.1.8072.2.255.2.1.3"] = "netSnmpPassOID",
                ["1.3.6.1.4.1.8072.2.255.3"] = "netSnmpPassTimeTicks",
                ["1.3.6.1.4.1.8072.2.255.4"] = "netSnmpPassIpAddress",
                ["1.3.6.1.4.1.8072.2.255.5"] = "netSnmpPassCounter",
                ["1.3.6.1.4.1.8072.2.255.6"] = "netSnmpPassGauge",
                ["1.3.6.1.4.1.8072.2.255.99"] = "netSnmpPassOIDValue",
                ["1.3.6.1.4.1.8072.3"] = "netSnmpEnumerations",
                ["1.3.6.1.4.1.8072.3.1"] = "netSnmpModuleIDs",
                ["1.3.6.1.4.1.8072.3.1.2"] = "netSnmpAgentMIB",
                ["1.3.6.1.4.1.8072.3.2"] = "netSnmpAgentOIDs",
                ["1.3.6.1.4.1.8072.3.3"] = "netSnmpDomains",
                ["1.3.6.1.4.1.8072.4"] = "netSnmpNotificationPrefix",
                ["1.3.6.1.4.1.8072.4.0"] = "netSnmpNotifications",
                ["1.3.6.1.4.1.8072.4.0.1"] = "nsNotifyStart",
                ["1.3.6.1.4.1.8072.4.0.2"] = "nsNotifyShutdown",
                ["1.3.6.1.4.1.8072.4.0.3"] = "nsNotifyRestart",
                ["1.3.6.1.4.1.8072.4.1"] = "netSnmpNotificationObjects",
                ["1.3.6.1.4.1.8072.5"] = "netSnmpConformance",
                ["1.3.6.1.4.1.8072.5.1"] = "netSnmpCompliances",
                ["1.3.6.1.4.1.8072.5.2"] = "netSnmpGroups",
                ["1.3.6.1.4.1.8072.5.2.2"] = "nsModuleGroup",
                ["1.3.6.1.4.1.8072.5.2.4"] = "nsCacheGroup",
                ["1.3.6.1.4.1.8072.5.2.7"] = "nsConfigGroups",
                ["1.3.6.1.4.1.8072.5.2.7.1"] = "nsDebugGroup",
                ["1.3.6.1.4.1.8072.5.2.7.2"] = "nsLoggingGroup",
                ["1.3.6.1.4.1.8072.5.2.8"] = "nsTransactionGroup",
                ["1.3.6.1.4.1.8072.5.2.9"] = "nsAgentNotifyGroup",
                ["1.3.6.1.4.1.8072.9999"] = "netSnmpExperimental",
                ["1.3.6.1.4.1.8072.9999.9999"] = "netSnmpPlaypen",
                ["1.3.6.1.5"] = "security",
                ["1.3.6.1.6"] = "snmpV2",
                ["1.3.6.1.6.1"] = "snmpDomains",
                ["1.3.6.1.6.1.1"] = "snmpUDPDomain",
                ["1.3.6.1.6.1.2"] = "snmpCLNSDomain",
                ["1.3.6.1.6.1.3"] = "snmpCONSDomain",
                ["1.3.6.1.6.1.4"] = "snmpDDPDomain",
                ["1.3.6.1.6.1.5"] = "snmpIPXDomain",
                ["1.3.6.1.6.2"] = "snmpProxys",
                ["1.3.6.1.6.2.1"] = "rfc1157Proxy",
                ["1.3.6.1.6.2.1.1"] = "rfc1157Domain",
                ["1.3.6.1.6.3"] = "snmpModules",
                ["1.3.6.1.6.3.1"] = "snmpMIB",
                ["1.3.6.1.6.3.1.1"] = "snmpMIBObjects",
                ["1.3.6.1.6.3.1.1.4"] = "snmpTrap",
                ["1.3.6.1.6.3.1.1.4.1"] = "snmpTrapOID",
                ["1.3.6.1.6.3.1.1.4.3"] = "snmpTrapEnterprise",
                ["1.3.6.1.6.3.1.1.5"] = "snmpTraps",
                ["1.3.6.1.6.3.1.1.5.1"] = "coldStart",
                ["1.3.6.1.6.3.1.1.5.2"] = "warmStart",
                ["1.3.6.1.6.3.1.1.5.3"] = "linkDown",
                ["1.3.6.1.6.3.1.1.5.4"] = "linkUp",
                ["1.3.6.1.6.3.1.1.5.5"] = "authenticationFailure",
                ["1.3.6.1.6.3.1.1.6"] = "snmpSet",
                ["1.3.6.1.6.3.1.1.6.1"] = "snmpSetSerialNo",
                ["1.3.6.1.6.3.1.2"] = "snmpMIBConformance",
                ["1.3.6.1.6.3.1.2.1"] = "snmpMIBCompliances",
                ["1.3.6.1.6.3.1.2.1.2"] = "snmpBasicCompliance",
                ["1.3.6.1.6.3.1.2.1.3"] = "snmpBasicComplianceRev2",
                ["1.3.6.1.6.3.1.2.2"] = "snmpMIBGroups",
                ["1.3.6.1.6.3.1.2.2.5"] = "snmpSetGroup",
                ["1.3.6.1.6.3.1.2.2.6"] = "systemGroup",
                ["1.3.6.1.6.3.1.2.2.7"] = "snmpBasicNotificationsGroup",
                ["1.3.6.1.6.3.1.2.2.8"] = "snmpGroup",
                ["1.3.6.1.6.3.1.2.2.9"] = "snmpCommunityGroup",
                ["1.3.6.1.6.3.1.2.2.10"] = "snmpObsoleteGroup",
                ["1.3.6.1.6.3.1.2.2.11"] = "snmpWarmStartNotificationGroup",
                ["1.3.6.1.6.3.1.2.2.12"] = "snmpNotificationGroup",
                ["1.3.6.1.6.3.10"] = "snmpFrameworkMIB",
                ["1.3.6.1.6.3.10.1"] = "snmpFrameworkAdmin",
                ["1.3.6.1.6.3.10.1.1"] = "snmpAuthProtocols",
                ["1.3.6.1.6.3.10.1.1.1"] = "usmNoAuthProtocol",
                ["1.3.6.1.6.3.10.1.1.2"] = "usmHMACMD5AuthProtocol",
                ["1.3.6.1.6.3.10.1.1.3"] = "usmHMACSHAAuthProtocol",
                ["1.3.6.1.6.3.10.1.2"] = "snmpPrivProtocols",
                ["1.3.6.1.6.3.10.1.2.1"] = "usmNoPrivProtocol",
                ["1.3.6.1.6.3.10.1.2.2"] = "usmDESPrivProtocol",
                ["1.3.6.1.6.3.10.2"] = "snmpFrameworkMIBObjects",
                ["1.3.6.1.6.3.10.2.1"] = "snmpEngine",
                ["1.3.6.1.6.3.10.2.1.1"] = "snmpEngineID",
                ["1.3.6.1.6.3.10.2.1.2"] = "snmpEngineBoots",
                ["1.3.6.1.6.3.10.2.1.3"] = "snmpEngineTime",
                ["1.3.6.1.6.3.10.2.1.4"] = "snmpEngineMaxMessageSize",
                ["1.3.6.1.6.3.10.3"] = "snmpFrameworkMIBConformance",
                ["1.3.6.1.6.3.10.3.1"] = "snmpFrameworkMIBCompliances",
                ["1.3.6.1.6.3.10.3.1.1"] = "snmpFrameworkMIBCompliance",
                ["1.3.6.1.6.3.10.3.2"] = "snmpFrameworkMIBGroups",
                ["1.3.6.1.6.3.10.3.2.1"] = "snmpEngineGroup",
                ["1.3.6.1.6.3.11"] = "snmpMPDMIB",
                ["1.3.6.1.6.3.11.1"] = "snmpMPDAdmin",
                ["1.3.6.1.6.3.11.2"] = "snmpMPDMIBObjects",
                ["1.3.6.1.6.3.11.2.1"] = "snmpMPDStats",
                ["1.3.6.1.6.3.11.2.1.1"] = "snmpUnknownSecurityModels",
                ["1.3.6.1.6.3.11.2.1.2"] = "snmpInvalidMsgs",
                ["1.3.6.1.6.3.11.2.1.3"] = "snmpUnknownPDUHandlers",
                ["1.3.6.1.6.3.11.3"] = "snmpMPDMIBConformance",
                ["1.3.6.1.6.3.11.3.1"] = "snmpMPDMIBCompliances",
                ["1.3.6.1.6.3.11.3.1.1"] = "snmpMPDCompliance",
                ["1.3.6.1.6.3.11.3.2"] = "snmpMPDMIBGroups",
                ["1.3.6.1.6.3.11.3.2.1"] = "snmpMPDGroup",
                ["1.3.6.1.6.3.12"] = "snmpTargetMIB",
                ["1.3.6.1.6.3.12.1"] = "snmpTargetObjects",
                ["1.3.6.1.6.3.12.1.1"] = "snmpTargetSpinLock",
                ["1.3.6.1.6.3.12.1.2"] = "snmpTargetAddrTable",
                ["1.3.6.1.6.3.12.1.2.1"] = "snmpTargetAddrEntry",
                ["1.3.6.1.6.3.12.1.2.1.1"] = "snmpTargetAddrName",
                ["1.3.6.1.6.3.12.1.2.1.2"] = "snmpTargetAddrTDomain",
                ["1.3.6.1.6.3.12.1.2.1.3"] = "snmpTargetAddrTAddress",
                ["1.3.6.1.6.3.12.1.2.1.4"] = "snmpTargetAddrTimeout",
                ["1.3.6.1.6.3.12.1.2.1.5"] = "snmpTargetAddrRetryCount",
                ["1.3.6.1.6.3.12.1.2.1.6"] = "snmpTargetAddrTagList",
                ["1.3.6.1.6.3.12.1.2.1.7"] = "snmpTargetAddrParams",
                ["1.3.6.1.6.3.12.1.2.1.8"] = "snmpTargetAddrStorageType",
                ["1.3.6.1.6.3.12.1.2.1.9"] = "snmpTargetAddrRowStatus",
                ["1.3.6.1.6.3.12.1.3"] = "snmpTargetParamsTable",
                ["1.3.6.1.6.3.12.1.3.1"] = "snmpTargetParamsEntry",
                ["1.3.6.1.6.3.12.1.3.1.1"] = "snmpTargetParamsName",
                ["1.3.6.1.6.3.12.1.3.1.2"] = "snmpTargetParamsMPModel",
                ["1.3.6.1.6.3.12.1.3.1.3"] = "snmpTargetParamsSecurityModel",
                ["1.3.6.1.6.3.12.1.3.1.4"] = "snmpTargetParamsSecurityName",
                ["1.3.6.1.6.3.12.1.3.1.5"] = "snmpTargetParamsSecurityLevel",
                ["1.3.6.1.6.3.12.1.3.1.6"] = "snmpTargetParamsStorageType",
                ["1.3.6.1.6.3.12.1.3.1.7"] = "snmpTargetParamsRowStatus",
                ["1.3.6.1.6.3.12.1.4"] = "snmpUnavailableContexts",
                ["1.3.6.1.6.3.12.1.5"] = "snmpUnknownContexts",
                ["1.3.6.1.6.3.12.3"] = "snmpTargetConformance",
                ["1.3.6.1.6.3.12.3.1"] = "snmpTargetCompliances",
                ["1.3.6.1.6.3.12.3.1.1"] = "snmpTargetCommandResponderCompliance",
                ["1.3.6.1.6.3.12.3.2"] = "snmpTargetGroups",
                ["1.3.6.1.6.3.12.3.2.1"] = "snmpTargetBasicGroup",
                ["1.3.6.1.6.3.12.3.2.2"] = "snmpTargetResponseGroup",
                ["1.3.6.1.6.3.12.3.2.3"] = "snmpTargetCommandResponderGroup",
                ["1.3.6.1.6.3.13"] = "snmpNotificationMIB",
                ["1.3.6.1.6.3.13.1"] = "snmpNotifyObjects",
                ["1.3.6.1.6.3.13.1.1"] = "snmpNotifyTable",
                ["1.3.6.1.6.3.13.1.1.1"] = "snmpNotifyEntry",
                ["1.3.6.1.6.3.13.1.1.1.1"] = "snmpNotifyName",
                ["1.3.6.1.6.3.13.1.1.1.2"] = "snmpNotifyTag",
                ["1.3.6.1.6.3.13.1.1.1.3"] = "snmpNotifyType",
                ["1.3.6.1.6.3.13.1.1.1.4"] = "snmpNotifyStorageType",
                ["1.3.6.1.6.3.13.1.1.1.5"] = "snmpNotifyRowStatus",
                ["1.3.6.1.6.3.13.1.2"] = "snmpNotifyFilterProfileTable",
                ["1.3.6.1.6.3.13.1.2.1"] = "snmpNotifyFilterProfileEntry",
                ["1.3.6.1.6.3.13.1.2.1.1"] = "snmpNotifyFilterProfileName",
                ["1.3.6.1.6.3.13.1.2.1.2"] = "snmpNotifyFilterProfileStorType",
                ["1.3.6.1.6.3.13.1.2.1.3"] = "snmpNotifyFilterProfileRowStatus",
                ["1.3.6.1.6.3.13.1.3"] = "snmpNotifyFilterTable",
                ["1.3.6.1.6.3.13.1.3.1"] = "snmpNotifyFilterEntry",
                ["1.3.6.1.6.3.13.1.3.1.1"] = "snmpNotifyFilterSubtree",
                ["1.3.6.1.6.3.13.1.3.1.2"] = "snmpNotifyFilterMask",
                ["1.3.6.1.6.3.13.1.3.1.3"] = "snmpNotifyFilterType",
                ["1.3.6.1.6.3.13.1.3.1.4"] = "snmpNotifyFilterStorageType",
                ["1.3.6.1.6.3.13.1.3.1.5"] = "snmpNotifyFilterRowStatus",
                ["1.3.6.1.6.3.13.3"] = "snmpNotifyConformance",
                ["1.3.6.1.6.3.13.3.1"] = "snmpNotifyCompliances",
                ["1.3.6.1.6.3.13.3.1.1"] = "snmpNotifyBasicCompliance",
                ["1.3.6.1.6.3.13.3.1.2"] = "snmpNotifyBasicFiltersCompliance",
                ["1.3.6.1.6.3.13.3.1.3"] = "snmpNotifyFullCompliance",
                ["1.3.6.1.6.3.13.3.2"] = "snmpNotifyGroups",
                ["1.3.6.1.6.3.13.3.2.1"] = "snmpNotifyGroup",
                ["1.3.6.1.6.3.13.3.2.2"] = "snmpNotifyFilterGroup",
                ["1.3.6.1.6.3.15"] = "snmpUsmMIB",
                ["1.3.6.1.6.3.15.1"] = "usmMIBObjects",
                ["1.3.6.1.6.3.15.1.1"] = "usmStats",
                ["1.3.6.1.6.3.15.1.1.1"] = "usmStatsUnsupportedSecLevels",
                ["1.3.6.1.6.3.15.1.1.2"] = "usmStatsNotInTimeWindows",
                ["1.3.6.1.6.3.15.1.1.3"] = "usmStatsUnknownUserNames",
                ["1.3.6.1.6.3.15.1.1.4"] = "usmStatsUnknownEngineIDs",
                ["1.3.6.1.6.3.15.1.1.5"] = "usmStatsWrongDigests",
                ["1.3.6.1.6.3.15.1.1.6"] = "usmStatsDecryptionErrors",
                ["1.3.6.1.6.3.15.1.2"] = "usmUser",
                ["1.3.6.1.6.3.15.1.2.1"] = "usmUserSpinLock",
                ["1.3.6.1.6.3.15.1.2.2"] = "usmUserTable",
                ["1.3.6.1.6.3.15.1.2.2.1"] = "usmUserEntry",
                ["1.3.6.1.6.3.15.1.2.2.1.1"] = "usmUserEngineID",
                ["1.3.6.1.6.3.15.1.2.2.1.2"] = "usmUserName",
                ["1.3.6.1.6.3.15.1.2.2.1.3"] = "usmUserSecurityName",
                ["1.3.6.1.6.3.15.1.2.2.1.4"] = "usmUserCloneFrom",
                ["1.3.6.1.6.3.15.1.2.2.1.5"] = "usmUserAuthProtocol",
                ["1.3.6.1.6.3.15.1.2.2.1.6"] = "usmUserAuthKeyChange",
                ["1.3.6.1.6.3.15.1.2.2.1.7"] = "usmUserOwnAuthKeyChange",
                ["1.3.6.1.6.3.15.1.2.2.1.8"] = "usmUserPrivProtocol",
                ["1.3.6.1.6.3.15.1.2.2.1.9"] = "usmUserPrivKeyChange",
                ["1.3.6.1.6.3.15.1.2.2.1.10"] = "usmUserOwnPrivKeyChange",
                ["1.3.6.1.6.3.15.1.2.2.1.11"] = "usmUserPublic",
                ["1.3.6.1.6.3.15.1.2.2.1.12"] = "usmUserStorageType",
                ["1.3.6.1.6.3.15.1.2.2.1.13"] = "usmUserStatus",
                ["1.3.6.1.6.3.15.2"] = "usmMIBConformance",
                ["1.3.6.1.6.3.15.2.1"] = "usmMIBCompliances",
                ["1.3.6.1.6.3.15.2.1.1"] = "usmMIBCompliance",
                ["1.3.6.1.6.3.15.2.2"] = "usmMIBGroups",
                ["1.3.6.1.6.3.15.2.2.1"] = "usmMIBBasicGroup",
                ["1.3.6.1.6.3.16"] = "snmpVacmMIB",
                ["1.3.6.1.6.3.16.1"] = "vacmMIBObjects",
                ["1.3.6.1.6.3.16.1.1"] = "vacmContextTable",
                ["1.3.6.1.6.3.16.1.1.1"] = "vacmContextEntry",
                ["1.3.6.1.6.3.16.1.1.1.1"] = "vacmContextName",
                ["1.3.6.1.6.3.16.1.2"] = "vacmSecurityToGroupTable",
                ["1.3.6.1.6.3.16.1.2.1"] = "vacmSecurityToGroupEntry",
                ["1.3.6.1.6.3.16.1.2.1.1"] = "vacmSecurityModel",
                ["1.3.6.1.6.3.16.1.2.1.2"] = "vacmSecurityName",
                ["1.3.6.1.6.3.16.1.2.1.3"] = "vacmGroupName",
                ["1.3.6.1.6.3.16.1.2.1.4"] = "vacmSecurityToGroupStorageType",
                ["1.3.6.1.6.3.16.1.2.1.5"] = "vacmSecurityToGroupStatus",
                ["1.3.6.1.6.3.16.1.4"] = "vacmAccessTable",
                ["1.3.6.1.6.3.16.1.4.1"] = "vacmAccessEntry",
                ["1.3.6.1.6.3.16.1.4.1.1"] = "vacmAccessContextPrefix",
                ["1.3.6.1.6.3.16.1.4.1.2"] = "vacmAccessSecurityModel",
                ["1.3.6.1.6.3.16.1.4.1.3"] = "vacmAccessSecurityLevel",
                ["1.3.6.1.6.3.16.1.4.1.4"] = "vacmAccessContextMatch",
                ["1.3.6.1.6.3.16.1.4.1.5"] = "vacmAccessReadViewName",
                ["1.3.6.1.6.3.16.1.4.1.6"] = "vacmAccessWriteViewName",
                ["1.3.6.1.6.3.16.1.4.1.7"] = "vacmAccessNotifyViewName",
                ["1.3.6.1.6.3.16.1.4.1.8"] = "vacmAccessStorageType",
                ["1.3.6.1.6.3.16.1.4.1.9"] = "vacmAccessStatus",
                ["1.3.6.1.6.3.16.1.5"] = "vacmMIBViews",
                ["1.3.6.1.6.3.16.1.5.1"] = "vacmViewSpinLock",
                ["1.3.6.1.6.3.16.1.5.2"] = "vacmViewTreeFamilyTable",
                ["1.3.6.1.6.3.16.1.5.2.1"] = "vacmViewTreeFamilyEntry",
                ["1.3.6.1.6.3.16.1.5.2.1.1"] = "vacmViewTreeFamilyViewName",
                ["1.3.6.1.6.3.16.1.5.2.1.2"] = "vacmViewTreeFamilySubtree",
                ["1.3.6.1.6.3.16.1.5.2.1.3"] = "vacmViewTreeFamilyMask",
                ["1.3.6.1.6.3.16.1.5.2.1.4"] = "vacmViewTreeFamilyType",
                ["1.3.6.1.6.3.16.1.5.2.1.5"] = "vacmViewTreeFamilyStorageType",
                ["1.3.6.1.6.3.16.1.5.2.1.6"] = "vacmViewTreeFamilyStatus",
                ["1.3.6.1.6.3.16.2"] = "vacmMIBConformance",
                ["1.3.6.1.6.3.16.2.1"] = "vacmMIBCompliances",
                ["1.3.6.1.6.3.16.2.1.1"] = "vacmMIBCompliance",
                ["1.3.6.1.6.3.16.2.2"] = "vacmMIBGroups",
                ["1.3.6.1.6.3.16.2.2.1"] = "vacmBasicGroup",
                ["1.3.6.1.6.3.18"] = "snmpCommunityMIB",
                ["1.3.6.1.6.3.18.1"] = "snmpCommunityMIBObjects",
                ["1.3.6.1.6.3.18.1.1"] = "snmpCommunityTable",
                ["1.3.6.1.6.3.18.1.1.1"] = "snmpCommunityEntry",
                ["1.3.6.1.6.3.18.1.1.1.1"] = "snmpCommunityIndex",
                ["1.3.6.1.6.3.18.1.1.1.2"] = "snmpCommunityName",
                ["1.3.6.1.6.3.18.1.1.1.3"] = "snmpCommunitySecurityName",
                ["1.3.6.1.6.3.18.1.1.1.4"] = "snmpCommunityContextEngineID",
                ["1.3.6.1.6.3.18.1.1.1.5"] = "snmpCommunityContextName",
                ["1.3.6.1.6.3.18.1.1.1.6"] = "snmpCommunityTransportTag",
                ["1.3.6.1.6.3.18.1.1.1.7"] = "snmpCommunityStorageType",
                ["1.3.6.1.6.3.18.1.1.1.8"] = "snmpCommunityStatus",
                ["1.3.6.1.6.3.18.1.2"] = "snmpTargetAddrExtTable",
                ["1.3.6.1.6.3.18.1.2.1"] = "snmpTargetAddrExtEntry",
                ["1.3.6.1.6.3.18.1.2.1.1"] = "snmpTargetAddrTMask",
                ["1.3.6.1.6.3.18.1.2.1.2"] = "snmpTargetAddrMMS",
                ["1.3.6.1.6.3.18.1.3"] = "snmpTrapAddress",
                ["1.3.6.1.6.3.18.1.4"] = "snmpTrapCommunity",
                ["1.3.6.1.6.3.18.2"] = "snmpCommunityMIBConformance",
                ["1.3.6.1.6.3.18.2.1"] = "snmpCommunityMIBCompliances",
                ["1.3.6.1.6.3.18.2.1.1"] = "snmpCommunityMIBCompliance",
                ["1.3.6.1.6.3.18.2.1.2"] = "snmpProxyTrapForwardCompliance",
                ["1.3.6.1.6.3.18.2.2"] = "snmpCommunityMIBGroups",
                ["1.3.6.1.6.3.18.2.2.1"] = "snmpCommunityGroup",
                ["1.3.6.1.6.3.18.2.2.3"] = "snmpProxyTrapForwardGroup",
                ["1.3.6.1.6.3.19"] = "snmpv2tm",
                ["0.0"] = "zeroDotZero",
})

function friendlyOID(oidNumeric)
    -- start with the two top-level sub-oid's
    local dotPosition = string.find(oidNumeric, "%.", 1)
    if dotPosition then
        dotPosition = string.find(oidNumeric, "%.", dotPosition + 1)
        if dotPosition then
            local lastDot = 0
            local oid, oidSub = {}
            while dotPosition do
                local oidSubNumeric = string.sub(oidNumeric, 1, dotPosition - 1)
                oidSub = OIDTable[oidSubNumeric]
                if oidSub then
                    table.insert(oid, oidSub)
                    lastDot = dotPosition
                    dotPosition = string.find(oidNumeric, "%.", dotPosition + 1)
                    if dotPosition then
                        table.insert(oid, ".")
                    end
                else
                    table.insert(oid, string.sub(oidNumeric, lastDot + 1, -1))
                    break
                end
            end
            -- last numeric subOID won't be terminated with a "."
            table.insert(oid, ".")
            oidSub = OIDTable[oidNumeric]
            if oidSub then
                table.insert(oid, oidSub)
            else
                table.insert(oid, string.sub(oidNumeric, lastDot + 1, -1))
            end
            return table.concat(oid)
        end
    end
    return oidNumeric
end