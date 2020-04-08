local parserName = "MAIL_lua"
local parserVersion = "2020.03.31.1"

local mailParser = nw.createParser(parserName, "Internet Message Format")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Extracts values from email messages such as email addresses,
subject, and client.

Parsing of an Internet Message Format message (RFC 5322) is
independent of the transport of the message (SMTP, POP, IMAP,
LMTP, etc.).  Think of the relationship as that between HTML
and HTTP - this parses the equivalent of HTML, not HTTP.

Meta "content" of an attachment is the literal value of the
Content-Type: header, which is easily forged.  Do not consider
content meta as any more authoritative than you would a filename
extension.
]=]

--[[
    VERSION

        2020.03.31.1  william motley          11.5.0.0-11048.5  bugfix defect in header collection when first line doesn't have header type and value
        2020.03.23.1  william motley          11.5.0.0-10941.5  collect all headers - even those we don't otherwise know about
                                                                register fullname.src and fullname.dst if registerSrcDst enabled
        2019.10.25.1  william motley          11.4.0.0-10470.5  detect forged sender
        2019.06.04.1  william motley          11.4.0.0-10087.1  bugfix: support custom headers even if unknown
                                                                customHeaders key name containing underscore is valid, hyphen is not
        2019.03.12.1  william motley          11.4.0.0-9744.3   tweak limitations on header block size
        2019.03.12.1  william motley          11.4.0.0-9744.3   go back to pcall createMeta if there's a charset, but now if fail then register w/o charset
        2019.02.25.1  william motley          11.4.0.0-9744.3   check for self.sessionVars before setting orgSrc
        2019.01.14.1  william motley          11.3.0.0.9710.1   accomodate 11.3+ callback order
        2018.11.13.1  william motley          11.3.0.0-9462.3   use transactions if 11.3+
        2018.08.30.1  william motley          11.3.0.0-9462.3   add hook for phishing module
                                                                add customHeaders option
        2018.08.13.1  william motley          11.3.0.0-9488.1   bugfix some content headers ignored
        2018.05.29.1  william motley          11.2.0.0-9060.3   analysis.service:  base64 email attachment
        2018.02.27.1  william motley          11.1.0.0-8987.3   UDM
        2018.02.02.1  william motley          11.1.0.0-8873.3   accomodate multiple RFC2407 charsets if identical
        2017.01.15.1  william motley          11.1.0.0-8873.3   accomodate non-RFC-compliant mime boundary terminations
                                                                improve extraction of fullname
        2017.09.15.1  william motley          11.0.0.0-8709.3   support extraction of address comment as "fullname"
                                                                bugfix content-disposition meta not registered
                                                                tweak header block size limit algorithm
        2017.04.27.1  william motley          10.6.3.1-7119.3   change mechanism for header block size limit
                                                                add extraction of addresses from resent-type headers
        2017.03.06.1  william motley          10.6.3.0-7095.3   bugfix content header block size not limited correctly in some limited circumstances
                                                                check for the presence of a '@' in email address for all charsets
        2017.02.07.2  william motley          10.6.3.0-7095.3   tweak header block size limits - allow up to 32KB for SMTP, IMAP, et al
                                                                bugfix multiple spaces in content-type header
                                                                added date and message-id mail header functions for identification only (no extraction)
        2016.10.12.1  william motley          11.0.0.0-7840.3   allow larger header blocks in some circumstances
                                                                accomodate unquoted boundary definitions
        2016.09.02.1  william motley          11.0.0.0-7769.3   pcall nw.createMeta if there's a charset
        2016.09.02.1  william motley          11.0.0.0-7769.3   option xmailer duplicates client, not replaces
                                                                replace ir.general and ir.alert (analysis.service, ioc)
        2016.08.17.1  william motley          10.6.1.0-7012     add IR meta
                                                                limit length of header block
                                                                limit length of header line
                                                                don't count token matches
                                                                add option to register mailer to different key
                                                                bugfix parseQuoted when true
        2016.05.16.1  william motley          10.6.0.1.7086.2   complete rewrite - substantial performance and meta improvement
                                                                renamed "ignoremimeboundaries" to "parsequoted"
        2016.01.07.1  william motley          10.6.0.0.6817     accomodate missing client self id in received header
        2015.09.11.1  william motley          10.6.0.0.5648     reformat comments
        2015.06.24.1  william motley          10.5.0.0.4961     support RFC2047-encoded attachment filenames
                                                                correct decoding of RFC2047 underscores
        2014.12.19.1  william motley          10.4.1.0.3425     bugfix received headers
        2014.08.01.1  william motley          10.4.0.0.3187     Rework how options are set
        2014.03.24.1  william motley          10.3.2.2256       support RFC2047-encoded email addresses
        2014.02.12.2  william motley          10.3.2.2256       rework stripping brackets and chevrons from addresses
                                                                add "Register Address Hosts" options
        2013.12.19.1  william motley          10.3.2.2256       scrub unprintable characters from subject meta
        2013.12.16.1  william motley          10.3.2.2256       support RFC2047-encoded subject header
        2013.11.08.1  william motley          10.3.0.1920       support RFC2231-formatted attachment headers
        2013.10.28.1  william motley          10.3.0.1920       remove requirement of date and originator
                                                                raise required number of headers 4 -> 5
        2013.10.21.2  william motley          10.3.0.1920       strip "mailto:" from email addresses
                                                                add auth results and cloudmark headers
        2013.10.18.1  william motley          10.3.0.1920       add precedence, domainkey, and list headers
        2013.08.27.1  william motley          10.3.0.1506       rework how headers are counted
        2013.06.17.1  william motley          10.2.5.1ish       assigned alert.id's
        2013.06.11.1  william motley          10.2.5.1ish       don't refer to "first" and "last" for an endOfStream callback
        2013.05.02.2  william motley          10.2.5.2          payload:short -> payload:uint16
                                                                payload:int -> payload:uint32
                                                                payload:byte -> payload:uint8
        2013.04.12.1  william motley          10.2.0.212        multipart mime detection
                                                                email-ip detection
                                                                parse RECEIVED headers
        2012.11.28.2  william motley          9.8.1.50          Initial development


    OPTIONS

        "Register email.src and email.dst": default FALSE

            Whether to register email address meta using the index keys
            "email.src" and "email.dst".

            If set to FALSE, all email address meta is registered with
            the index key "email".

            If set to TRUE:

             - Originating email addresses will be registered with the index
               key "email.src"

             - Recipient email addresses will be registered with the index
               key "email.dst"

        "Parse Quoted Messages" : default FALSE

            Whether to register meta from mail headers which are part of a
            quoted message.

        "Register Address Hosts" : default FALSE

            Whether to register the host portion of email addresses as meta.

            The key used to register will be alias.host, alias.ip, or
            alias.ipv6 as appropriate.

        "Parse Received headers" : default TRUE

            Whether to register meta from Received: headers.

            Many MTAs put all sorts of badly formatted information into
            "Received:" headers.  Most likely this will manifest as alias.host
            meta that isn't a hostname.

            If this is problematic in your environment, disable parsing of
            Received: headers.

        "X-Mailer Key" : default "client"

            Default behavior is to register the value of X-Mailer headers with the 'mailer'
            index key.

            Modifying this value will cause X-Mailer values to as well be registered with
            the specified key.  If the key does not already exist it will be created - normal
            key name restrictions apply.
            
        "Custom Headers" : default NONE
    
            Beware of excessive duplication, which will impact performance and retention.  Meta
            registered will be in addition to, not replacement of, standard meta registration.
            In other words, if you specify "subject" headers be registered to key "foo", it
            will still also be registered to subject.
            
            Syntax is,
            
                {
                    ["header"] = "key",
                    ["header"] = "key",
                }
                
            Where,
            
                "header" is the desired HTTP header in lowercase.  Do not included spaces, colons, etc.
                
                "key" is the desired meta key with which to register the value of that header
            
            Key names must be 16 characters or less, and consist only of letters and dots.  Keys
            specified that do not meet these requirements will be modified in order to conform.
            
            Keys listed here are registered as format="Text".  Don't use keys indexed as other formats.
            
            Changes to this option require a restart of the decoder service.  Simply reloading
            parsers is not sufficient for changes to take effect.


    IMPLEMENTATION

        A block of headers must contain a total of at least 5 mail-like headers.
        If that requirement is not fulfilled, then no meta is registered for
        that block.

        Meta "group" ostensibly is registered by the native parser.  However,
        I've never seen it registered, and I have no idea what it would be.
        Therefore, meta "group" is not registered by this parser.

        The native parser sometimes registers content "message/rfc822",
        sometimes content "mail", sometimes both.  I can't determine why one
        or the other.  This parser simply registers content meta "mail".

        In order to not register meta from headers in messages that are
        attached to a message, the parser keeps track of mime boundaries.
        When an "outer" boundary is seen, only attachment headers are
        extracted until the boundary termination is seen.  When an "inner"
        boundary is seen, no headers are extracted until the boundary
        termination is seen.

        Notes on RFC 2047 and RFC 2231 encoding:
        
            MULTIPLE CHARACTER SETS

                Multiple charsets within the same string are allowed.
    
                    E.g. part ISO-2022-JP and part is windows-1256
    
                Furthermore, multiple encodings are also allowed.
    
                    E.g. part is quoted-printable, part is base64
    
                There is no way to register multiple character sets for
                the same meta value.  The only possible solution would be
                to register multiple meta values (one for each charset).
    
                However, this parser currently DOES NOT do that.  Only
                ONE meta value is registered, even if there may be multiple
                character sets and/or encodings.
                
            SUPPORTED CHARACTER SETS
                
                Character sets supported by decoder should be those supported
                by iconv:
            
                    http://www.delorie.com/gnu/docs/recode/recode_30.html
                
                The ramification though is that different versions of decoder
                can and will have different versions of iconv.  Registering
                meta specifying an unsupported set results in a parser error.
                
                So the parser wraps nw.createMeta() in a pcall when meta
                with a character set is to be registered.  In case that fails,
                the parser tries again without specifying a character set.


    TODO

        Extract/register meta "group" (see NOTES above).

        Register multiple meta values for multiple RFC 2047/RFC 2231 character sets?

--]]

summary.dependencies = {
    ["parsers"] = {
        "FeedParser",
        "nwll"
    },
    ["feeds"] = {
        "investigation"
    }
}

summary.softDependencies = {
    ["parsers"] = {
        "SMTP_lua",
    }
}

summary.conflicts = {
    ["parsers"] = {
        "MAIL",
        "MAIL-flex",
        "email-ip"
    }
}

summary.keyUsage = {
    ["action"]            = "mail action performed: 'sendfrom, 'sendto', 'attach'",
    ["alias.host"]        = "hostname values from x-originating-ip headers, received headers, and (optional) email addresses",
    ["alias.ip"]          = "ipv4 values from x-originating-ip headers, received headers, and (optional) email addresses",
    ["alias.ipv6"]        = "ipv6 values from x-originating-ip headers, received headers, and (optional) email addresses",
    ["attachment"]        = "filenames of email attachments",
    ["client"]            = "values from x-mailer: headers",
    ["content"]           = "'mail', value of Content-Type headers within messages",
    ["email"]             = "email address found within messages",
    ["email.dst"]         = "(optional) message recipients",
    ["email.src"]         = "(optional) message originators",
    ["extension"]         = "extension from filenames of email attachments",
    ["fullname"]          = "comment portion of addresses, typically a name",
    ["fullname.dst"]      = "(optional) comment portion of recipient addresses",
    ["fullname.src"]      = "(optional) comment portion of sender addresses",
    ["subject"]           = "values from subject: headers",
    ["analysis.service"]  = "characteristics of email messages",
    ["ioc"]               = "indicators of compromise",
}

summary.investigation = {
    ["analysis.service"] = {
        ["email recipients cc/bcc only"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "An email does not specify a 'To' recipient",
            ["reason"] = "Attempt to hide message recipients.",
        },
        ["email missing recipients"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "An email contains no 'To', 'cc', or 'bcc' recipients",
            ["reason"] = "Attempt to hide message recipients.",
        },
        ["email address domain is an IP"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
            },
            ["description"] = "An email address of the form 'user@1.2.3.4'",
            ["reason"] = "Direct to IP email addresses are unusual and suspicious.",
        },
        ["received header hostname mismatch"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "A client email server claims to be a host other than the reverse of its IP address.",
            ["reason"] = "Attempt to masquerade as a legitimate host.",
        },
        ["received header IP mismatch"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "The reverse of a client email server's hostname differs from the IP address from which it connected.",
            ["reason"] = "Attempt to masquerade as a legitimate host.",
        },
        ["express x-mailer"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
            },
            ["description"] = "Email client contains 'express'",
            ["reason"] = "Express Mailer is often used for phishing campaigns.",
        },
        ["inbound email"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "Email source is external to the environment.",
            ["reason"] = "Filter for incoming email.",
        },
        ["uncommon mail source"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "Incoming email from a source not commonly known for sending email.",
            ["reason"] = "Filter for incoming email.",
        },
        ["subject phish"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "event analysis",
                "protocol analysis",
            },
            ["description"] = "Incoming email from an uncommon source with a subject containing a important seeming keyword.",
            ["reason"] = "Characteristics common to phishing emails.",
        },
        ["base64 email attachment"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "protocol analysis",
            },
            ["description"] = "email message contains base64 encoded attachment",
            ["reason"] = "Filter for email.  Most email attachments are base64",
        },
        ["smtp forged sender"] = {
            ["inv.category"] = {
                "operations",
            },
            ["inv.context"] = {
                "protocol analysis",
            },
            ["description"] = "SMTP protocol sender doesn't match envelope sender",
            ["reason"] = "Commonly seen from distribution lists, etc.  When combined with other characteristics, possibily indicative of phishing.",
        },
    },
    ["ioc"] = {
        ["Elderwood XMailer Artifact"] = {
            ["inv.category"] = {
                "threat",
            },
            ["inv.context"] = {
                "attack phase",
                "delivery",
            },
            ["description"] = "Email client seen involved with the Elder Wood campaign.",
            ["reason"] = "Indicates that an email is likely a phishing attempt.",
            ["mitre"] = {
            },
        },
    },
}

summary.liveTags = {
    "featured",
    "operations",
    "event analysis",
    "application analysis",
}

local nwll = require("nwll")

local phishingModule
pcall(
    function()
        phishingModule = require('phishing')
        if not (phishingModule and type(phishingModule) == "table" and phishingModule.examine) then
            phishingModule = nil
        end
    end
)

-- define options
    local options = ({
        ["registerEmailSrcDst"] = ({
            ["name"] = "Register email.src and email.dst",
            ["description"] = "Register email meta using index keys email.src and email.dst",
            ["type"] = "boolean",
            ["default"] = false,
        }),
        ["parseQuoted"] = ({
            ["name"] = "Parse Quoted Messages",
            ["description"] = "Register meta from headers within quoted messages.",
            ["type"] = "boolean",
            ["default"] = false,
        }),
        ["registerAddressHosts"] = ({
            ["name"] = "Register Address Hosts",
            ["description"] = "Register host portion of email addresses.",
            ["type"] = "boolean",
            ["default"] = false,
        }),
        ["parseReceived"] = ({
            ["name"] = "Parse Received headers",
            ["description"] = "Register meta from Received: headers",
            ["type"] = "boolean",
            ["default"] = true
        }),
        ["xmailer"] = {
            ["name"] = "X-Mailer Key",
            ["description"] = "Register the values of X-Mailer headers with this key",
            ["type"] = "string",
            ["default"] = "client"
        },
        ["customHeaders"] = {
            ["name"] = "Custom Headers",
            ["description"] = "Other headers for which to register meta",
            ["type"] = "table",
            ["default"] = nil
        }
    })
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
        if parameters.type == "number" then
            parameters.value = tonumber(parameters.value)
        end
        if type(parameters.value) ~= parameters.type then
            parameters.value = parameters.default
        elseif parameters.type == "number" then
            parameters.value =
                (parameters.minimum and parameters.value < parameters.minimum and parameters.minimum) or
                (parameters.maximum and parameters.value > parameters.maximum and parameters.maximum) or
                parameters.value
        end
    end
-- end options

local indexKeys = {}
table.insert(indexKeys, nwlanguagekey.create("action"))
table.insert(indexKeys, nwlanguagekey.create("content"))
table.insert(indexKeys, nwlanguagekey.create("email"))
table.insert(indexKeys, nwlanguagekey.create("fullname"))
table.insert(indexKeys, nwlanguagekey.create("alias.host"))
table.insert(indexKeys, nwlanguagekey.create("client"))
table.insert(indexKeys, nwlanguagekey.create("alias.ip", nwtypes.IPv4))
table.insert(indexKeys, nwlanguagekey.create("alias.ipv6",nwtypes.IPv6))
table.insert(indexKeys, nwlanguagekey.create("subject"))
table.insert(indexKeys, nwlanguagekey.create("attachment"))
table.insert(indexKeys, nwlanguagekey.create("extension"))
table.insert(indexKeys, nwlanguagekey.create("analysis.service"))
table.insert(indexKeys, nwlanguagekey.create("ioc"))
if options.xmailer.value and options.xmailer.value ~= "client" then
    table.insert(indexKeys, nwlanguagekey.create(options.xmailer.value, nwtypes.Text))
end
if options.registerEmailSrcDst.value then
    table.insert(indexKeys, nwlanguagekey.create("email.src"))
    table.insert(indexKeys, nwlanguagekey.create("email.dst"))
    table.insert(indexKeys, nwlanguagekey.create("fullname.src"))
    table.insert(indexKeys, nwlanguagekey.create("fullname.dst"))
end
if options.customHeaders.value then
    local sanitized = {}
    for header, key in pairs(options.customHeaders.value) do
        local orig_key = key
        if type(header) == "string" and #header ~= 0 and type(key) == "string" and #key ~= 0 then
            header = string.lower(header)
            header = string.gsub(header, "[:%s]+$", "")
            if header and #header ~= 0 then
                key = string.gsub(key, "[^%w^%.^_]", "")
                key = (#key <= 16 and key) or string.sub(key, 1, 16)
                if #key ~= 0 then
                    table.insert(indexKeys, nwlanguagekey.create(key))
                    sanitized[header] = key
                    if key ~= orig_key then
                        nw.logWarning("MAIL_lua: '" .. orig_key .. "' sanitized to '" .. key .. "'")
                    end
                else
                    nw.logFailure("MAIL_lua: cannot use key '" .. orig_key .. "'")
                end
            end
        end
    end
    options.customHeaders.value = sanitized
end

mailParser:setKeys(indexKeys)

local version
pcall(
    function()
        local major, minor = nw.getVersion()
        version = major .. "." .. minor
        version = tonumber(version)
    end
)
version = version or 0 

-- Only use transactions if version >= 11.3
local transactions = (version >= 11.3 and true) or false

local SMTP_lua

local function createMeta(xid, key, value, charset)
    if key and value then
        local registered
        if transactions and xid then
            if charset then
                -- first try adding WITH the charset
                registered = pcall(function() xid:addMeta(key, value, charset) end)
            end
            if not registered then
                -- add WITHOUT the charset
                xid:addMeta(key, value)
            end
        else
            if charset then
                -- first try creating WITH the charset
                registered = pcall(function() nw.createMeta(key, value, charset) end)
            end
            if not registered then
                -- create WITHOUT the charset
                nw.createMeta(key, value)
            end
        end
    end
end

local commonOrgSources = {
    ["exacttarget"] = true,
    ["constant contact"] = true,
    ["responsys"] = true,
    ["sitewire marketspace solutions"] = true,
    ["isdnet"] = true,
    ["e-dialog"] = true,
    ["linkedin corporation"] = true,
    ["qwest communications"] = true,
    ["silverpop systems"] = true,
    ["psinet"] = true,
    ["postini"] = true,
    ["cheetahmail"] = true,
    ["amazon.com"] = true,
    ["eloqua corporation"] = true,
    ["spark marketing llc"] = true,
    ["ibm-mgt"] = true,
    ["facebook"] = true,
    ["omeda communications"] = true,
    ["easystreet online services"] = true
}

local phishySubjects = {
    "update",
    "important",
    "notice",
    "attention",
    "please",
    "vpn",
}

local charsetAliases = {                -- supported character sets for RFC2047 encoding
    --General character sets
        ["US-ASCII"] = "US-ASCII",
        ["ASCII"] = "US-ASCII",
        ["ISO646-US"] = "US-ASCII",
        ["ISO_646.IRV:1991"] = "US-ASCII",
        ["ISO-IR-6"] = "US-ASCII",
        ["ANSI_X3.4-1968"] = "US-ASCII",
        ["CP367"] = "US-ASCII",
        ["IBM367"] = "US-ASCII",
        ["US"] = "US-ASCII",
        ["CSASCII"] = "US-ASCII",
        ["ISO646.1991-IRV"] = "US-ASCII",
    --General multi-byte encodings
        ["UTF-8"] = "UTF-8",
        ["UTF8"] = "UTF-8",
        ["UCS-2"] = "UCS-2",
        ["ISO-10646-UCS-2"] = "UCS-2",
        ["CSUNICODE"] = "UCS-2",
        ["UCS-2BE"] = "UCS-2BE",
        ["UNICODEBIG"] = "UCS-2BE",
        ["UNICODE-1-1"] = "UCS-2BE",
        ["CSUNICODE11"] = "UCS-2BE",
        ["UCS-2LE"] = "UCS-2LE",
        ["UNICODELITTLE"] = "UCS-2LE",
        ["UCS-4"] = "UCS-4",
        ["ISO-10646-UCS-4"] = "UCS-4",
        ["CSUCS4"] = "UCS-4",
        ["UCS-4BE"] = "UCS-4BE",
        ["UCS-4LE"] = "UCS-4LE",
        ["UTF-16"] = "UTF-16",
        ["UTF-16BE"] = "UTF-16BE",
        ["UTF-16LE"] = "UTF-16LE",
        ["UTF-7"] = "UTF-7",
        ["UNICODE-1-1-UTF-7"] = "UTF-7",
        ["CSUNICODE11UTF7"] = "UTF-7",
        ["UCS-2-INTERNAL"] = "UCS-2-INTERNAL",
        ["UCS-2-SWAPPED"] = "UCS-2-SWAPPED",
        ["UCS-4-INTERNAL"] = "UCS-4-INTERNAL",
        ["UCS-4-SWAPPED"] = "UCS-4-SWAPPED",
        ["JAVA"] = "JAVA",
    --Standard 8-bit encodings
        ["ISO-8859-1"] = "ISO-8859-1",
        ["ISO_8859-1"] = "ISO-8859-1",
        ["ISO_8859-1:1987"] = "ISO-8859-1",
        ["ISO-IR-100"] = "ISO-8859-1",
        ["CP819"] = "ISO-8859-1",
        ["IBM819"] = "ISO-8859-1",
        ["LATIN1"] = "ISO-8859-1",
        ["L1"] = "ISO-8859-1",
        ["CSISOLATIN1"] = "ISO-8859-1",
        ["ISO8859-1"] = "ISO-8859-1",
        ["ISO8859_1"] = "ISO-8859-1",
        ["ISO-8859-2"] = "ISO-8859-2",
        ["ISO_8859-2"] = "ISO-8859-2",
        ["ISO_8859-2:1987"] = "ISO-8859-2",
        ["ISO-IR-101"] = "ISO-8859-2",
        ["LATIN2"] = "ISO-8859-2",
        ["L2"] = "ISO-8859-2",
        ["CSISOLATIN2"] = "ISO-8859-2",
        ["ISO8859-2"] = "ISO-8859-2",
        ["ISO8859_2"] = "ISO-8859-2",
        ["ISO-8859-3"] = "ISO-8859-3",
        ["ISO_8859-3"] = "ISO-8859-3",
        ["ISO_8859-3:1988"] = "ISO-8859-3",
        ["ISO-IR-109"] = "ISO-8859-3",
        ["LATIN3"] = "ISO-8859-3",
        ["L3"] = "ISO-8859-3",
        ["CSISOLATIN3"] = "ISO-8859-3",
        ["ISO8859-3"] = "ISO-8859-3",
        ["ISO8859_3"] = "ISO-8859-3",
        ["ISO-8859-4"] = "ISO-8859-4",
        ["ISO_8859-4"] = "ISO-8859-4",
        ["ISO_8859-4:1988"] = "ISO-8859-4",
        ["ISO-IR-110"] = "ISO-8859-4",
        ["LATIN4"] = "ISO-8859-4",
        ["L4"] = "ISO-8859-4",
        ["CSISOLATIN4"] = "ISO-8859-4",
        ["ISO8859-4"] = "ISO-8859-4",
        ["ISO8859_4"] = "ISO-8859-4",
        ["ISO-8859-5"] = "ISO-8859-5",
        ["ISO_8859-5"] = "ISO-8859-5",
        ["ISO_8859-5:1988"] = "ISO-8859-5",
        ["ISO-IR-144"] = "ISO-8859-5",
        ["CYRILLIC"] = "ISO-8859-5",
        ["CSISOLATINCYRILLIC"] = "ISO-8859-5",
        ["ISO8859-5"] = "ISO-8859-5",
        ["ISO8859_5"] = "ISO-8859-5",
        ["ISO-8859-6"] = "ISO-8859-6",
        ["ISO_8859-6"] = "ISO-8859-6",
        ["ISO_8859-6:1987"] = "ISO-8859-6",
        ["ISO-IR-127"] = "ISO-8859-6",
        ["ECMA-114"] = "ISO-8859-6",
        ["ASMO-708"] = "ISO-8859-6",
        ["ARABIC"] = "ISO-8859-6",
        ["CSISOLATINARABIC"] = "ISO-8859-6",
        ["ISO8859-6"] = "ISO-8859-6",
        ["ISO8859_6"] = "ISO-8859-6",
        ["ISO-8859-7"] = "ISO-8859-7",
        ["ISO_8859-7"] = "ISO-8859-7",
        ["ISO_8859-7:1987"] = "ISO-8859-7",
        ["ISO-IR-126"] = "ISO-8859-7",
        ["ECMA-118"] = "ISO-8859-7",
        ["ELOT_928"] = "ISO-8859-7",
        ["GREEK8"] = "ISO-8859-7",
        ["GREEK"] = "ISO-8859-7",
        ["CSISOLATINGREEK"] = "ISO-8859-7",
        ["ISO8859-7"] = "ISO-8859-7",
        ["ISO8859_7"] = "ISO-8859-7",
        ["ISO-8859-8"] = "ISO-8859-8",
        ["ISO_8859-8"] = "ISO-8859-8",
        ["ISO-8859-8-I"] = "ISO-8859-8",
        ["ISO_8859-8:1988"] = "ISO-8859-8",
        ["ISO-IR-138"] = "ISO-8859-8",
        ["HEBREW"] = "ISO-8859-8",
        ["CSISOLATINHEBREW"] = "ISO-8859-8",
        ["ISO8859-8"] = "ISO-8859-8",
        ["ISO8859_8"] = "ISO-8859-8",
        ["ISO-8859-9"] = "ISO-8859-9",
        ["ISO_8859-9"] = "ISO-8859-9",
        ["ISO_8859-9:1989"] = "ISO-8859-9",
        ["ISO-IR-148"] = "ISO-8859-9",
        ["LATIN5"] = "ISO-8859-9",
        ["L5"] = "ISO-8859-9",
        ["CSISOLATIN5"] = "ISO-8859-9",
        ["ISO8859-9"] = "ISO-8859-9",
        ["ISO8859_9"] = "ISO-8859-9",
        ["ISO-8859-10"] = "ISO-8859-10",
        ["ISO_8859-10"] = "ISO-8859-10",
        ["ISO_8859-10:1992"] = "ISO-8859-10",
        ["ISO-IR-157"] = "ISO-8859-10",
        ["LATIN6"] = "ISO-8859-10",
        ["L6"] = "ISO-8859-10",
        ["CSISOLATIN6"] = "ISO-8859-10",
        ["ISO8859-10"] = "ISO-8859-10",
        ["ISO-8859-13"] = "ISO-8859-13",
        ["ISO_8859-13"] = "ISO-8859-13",
        ["ISO-IR-179"] = "ISO-8859-13",
        ["LATIN7"] = "ISO-8859-13",
        ["L7"] = "ISO-8859-13",
        ["ISO-8859-14"] = "ISO-8859-14",
        ["ISO_8859-14"] = "ISO-8859-14",
        ["ISO_8859-14:1998"] = "ISO-8859-14",
        ["ISO-IR-199"] = "ISO-8859-14",
        ["LATIN8"] = "ISO-8859-14",
        ["L8"] = "ISO-8859-14",
        ["ISO-8859-15"] = "ISO-8859-15",
        ["ISO_8859-15"] = "ISO-8859-15",
        ["ISO_8859-15:1998"] = "ISO-8859-15",
        ["ISO-IR-203"] = "ISO-8859-15",
        ["ISO-8859-16"] = "ISO-8859-16",
        ["ISO_8859-16"] = "ISO-8859-16",
        ["ISO_8859-16:2000"] = "ISO-8859-16",
        ["ISO-IR-226"] = "ISO-8859-16",
        ["KOI8-R"] = "KOI8-R",
        ["CSKOI8R"] = "KOI8-R",
        ["KOI8-U"] = "KOI8-U",
        ["KOI8-RU"] = "KOI8-RU",
    --Windows 8-bit encodings
        ["CP1250"] = "CP1250",
        ["WINDOWS-1250"] = "CP1250",
        ["MS-EE"] = "CP1250",
        ["CP1251"] = "CP1251",
        ["WINDOWS-1251"] = "CP1251",
        ["MS-CYRL"] = "CP1251",
        ["CP1252"] = "CP1252",
        ["WINDOWS-1252"] = "CP1252",
        ["MS-ANSI"] = "CP1252",
        ["CP1253"] = "CP1253",
        ["WINDOWS-1253"] = "CP1253",
        ["MS-GREEK"] = "CP1253",
        ["CP1254"] = "CP1254",
        ["WINDOWS-1254"] = "CP1254",
        ["MS-TURK"] = "CP1254",
        ["CP1255"] = "CP1255",
        ["WINDOWS-1255"] = "CP1255",
        ["MS-HEBR"] = "CP1255",
        ["CP1256"] = "CP1256",
        ["WINDOWS-1256"] = "CP1256",
        ["MS-ARAB"] = "CP1256",
        ["CP1257"] = "CP1257",
        ["WINDOWS-1257"] = "CP1257",
        ["WINBALTRIM"] = "CP1257",
        ["CP1258"] = "CP1258",
        ["WINDOWS-1258"] = "CP1258",
    --DOS 8-bit encodings
        ["CP850"] = "CP850",
        ["IBM850"] = "CP850",
        ["850"] = "CP850",
        ["CSPC850MULTILINGUAL"] = "CP850",
        ["CP866"] = "CP866",
        ["IBM866"] = "CP866",
        ["866"] = "CP866",
        ["CSIBM866"] = "CP866",
    --Macintosh 8-bit encodings
        ["MACROMAN"] = "MACROMAN",
        ["MACINTOSH"] = "MACROMAN",
        ["MAC"] = "MACROMAN",
        ["CSMACINTOSH"] = "MACROMAN",
        ["MACCENTRALEUROPE"] = "MACCENTRALEUROPE",
        ["MACICELAND"] = "MACICELAND",
        ["MACCROATIAN"] = "MACCROATIAN",
        ["MACROMANIA"] = "MACROMANIA",
        ["MACCYRILLIC"] = "MACCYRILLIC",
        ["MACUKRAINE"] = "MACUKRAINE",
        ["MACGREEK"] = "MACGREEK",
        ["MACTURKISH"] = "MACTURKISH",
        ["MACHEBREW"] = "MACHEBREW",
        ["MACARABIC"] = "MACARABIC",
        ["MACTHAI"] = "MACTHAI",
    --Other platform specific 8-bit encodings
        ["HP-ROMAN8"] = "HP-ROMAN8",
        ["ROMAN8"] = "HP-ROMAN8",
        ["R8"] = "HP-ROMAN8",
        ["CSHPROMAN8"] = "HP-ROMAN8",
        ["NEXTSTEP"] = "NEXTSTEP",
    --Regional 8-bit encodings used for a single language
        ["ARMSCII-8"] = "ARMSCII-8",
        ["GEORGIAN-ACADEMY"] = "GEORGIAN-ACADEMY",
        ["GEORGIAN-PS"] = "GEORGIAN-PS",
        ["MULELAO-1"] = "MULELAO-1",
        ["CP1133"] = "CP1133",
        ["IBM-CP1133"] = "CP1133",
        ["TIS-620"] = "TIS-620",
        ["TIS620"] = "TIS-620",
        ["TIS620-0"] = "TIS-620",
        ["TIS620.2529-1"] = "TIS-620",
        ["TIS620.2533-0"] = "TIS-620",
        ["TIS620.2533-1"] = "TIS-620",
        ["ISO-IR-166"] = "TIS-620",
        ["CP874"] = "CP874",
        ["WINDOWS-874"] = "CP874",
        ["VISCII"] = "VISCII",
        ["VISCII1.1-1"] = "VISCII",
        ["CSVISCII"] = "VISCII",
        ["TCVN"] = "TCVN",
        ["TCVN-5712"] = "TCVN",
        ["TCVN5712-1"] = "TCVN",
        ["TCVN5712-1:1993"] = "TCVN",
    --CJK character sets (not documented)
        ["JIS_C6220-1969-RO"] = "JIS_C6220-1969-RO",
        ["ISO646-JP"] = "JIS_C6220-1969-RO",
        ["ISO-IR-14"] = "JIS_C6220-1969-RO",
        ["JP"] = "JIS_C6220-1969-RO",
        ["CSISO14JISC6220RO"] = "JIS_C6220-1969-RO",
        ["JIS_X0201"] = "JIS_X0201",
        ["JISX0201-1976"] = "JIS_X0201",
        ["X0201"] = "JIS_X0201",
        ["CSHALFWIDTHKATAKANA"] = "JIS_X0201",
        ["JISX0201.1976-0"] = "JIS_X0201",
        ["JIS0201"] = "JIS_X0201",
        ["JIS_X0208"] = "JIS_X0208",
        ["JIS_X0208-1983"] = "JIS_X0208",
        ["JIS_X0208-1990"] = "JIS_X0208",
        ["JIS0208"] = "JIS_X0208",
        ["X0208"] = "JIS_X0208",
        ["ISO-IR-87"] = "JIS_X0208",
        ["CSISO87JISX0208"] = "JIS_X0208",
        ["JISX0208.1983-0"] = "JIS_X0208",
        ["JISX0208.1990-0"] = "JIS_X0208",
        ["JIS0208"] = "JIS_X0208",
        ["JIS_X0212"] = "JIS_X0212",
        ["JIS_X0212.1990-0"] = "JIS_X0212",
        ["JIS_X0212-1990"] = "JIS_X0212",
        ["X0212"] = "JIS_X0212",
        ["ISO-IR-159"] = "JIS_X0212",
        ["CSISO159JISX02121990"] = "JIS_X0212",
        ["JISX0212.1990-0"] = "JIS_X0212",
        ["JIS0212"] = "JIS_X0212",
        ["GB_1988-80"] = "GB_1988-80",
        ["ISO646-CN"] = "GB_1988-80",
        ["ISO-IR-57"] = "GB_1988-80",
        ["CN"] = "GB_1988-80",
        ["CSISO57GB1988"] = "GB_1988-80",
        ["GB_2312-80"] = "GB_2312-80",
        ["ISO-IR-58"] = "GB_2312-80",
        ["CSISO58GB231280"] = "GB_2312-80",
        ["CHINESE"] = "GB_2312-80",
        ["GB2312.1980-0"] = "GB_2312-80",
        ["ISO-IR-165"] = "ISO-IR-165",
        ["CN-GB-ISOIR165"] = "ISO-IR-165",
        ["KSC_5601"] = "KSC_5601",
        ["KS_C_5601-1987"] = "KSC_5601",
        ["KS_C_5601-1989"] = "KSC_5601",
        ["ISO-IR-149"] = "KSC_5601",
        ["CSKSC56011987"] = "KSC_5601",
        ["KOREAN"] = "KSC_5601",
        ["KSC5601.1987-0"] = "KSC_5601",
        ["KSX1001:1992"] = "KSC_5601",
    --CJK encodings
        ["EUC-JP"] = "EUC-JP",
        ["EUCJP"] = "EUC-JP",
        ["EXTENDED_UNIX_CODE_PACKED_FORMAT_FOR_JAPANESE"] = "EUC-JP",
        ["CSEUCPKDFMTJAPANESE"] = "EUC-JP",
        ["EUC_JP"] = "EUC-JP",
        ["SJIS"] = "SJIS",
        ["SHIFT_JIS"] = "SJIS",
        ["SHIFT-JIS"] = "SJIS",
        ["MS_KANJI"] = "SJIS",
        ["CSSHIFTJIS"] = "SJIS",
        ["CP932"] = "CP932",
        ["ISO-2022-JP"] = "ISO-2022-JP",
        ["CSISO2022JP"] = "ISO-2022-JP",
        ["ISO2022JP"] = "ISO-2022-JP",
        ["ISO-2022-JP-1"] = "ISO-2022-JP-1",
        ["ISO-2022-JP-2"] = "ISO-2022-JP-2",
        ["CSISO2022JP2"] = "ISO-2022-JP-2",
        ["EUC-CN"] = "EUC-CN",
        ["EUCCN"] = "EUC-CN",
        ["GB2312"] = "EUC-CN",
        ["CN-GB"] = "EUC-CN",
        ["CSGB2312"] = "EUC-CN",
        ["EUC_CN"] = "EUC-CN",
        ["GBK"] = "GBK",
        ["CP936"] = "GBK",
        ["GB18030"] = "GB18030",
        ["ISO-2022-CN"] = "ISO-2022-CN",
        ["CSISO2022CN"] = "ISO-2022-CN",
        ["ISO2022CN"] = "ISO-2022-CN",
        ["ISO-2022-CN-EXT"] = "ISO-2022-CN-EXT",
        ["HZ"] = "HZ",
        ["HZ-GB-2312"] = "HZ",
        ["EUC-TW"] = "EUC-TW",
        ["EUCTW"] = "EUC-TW",
        ["CSEUCTW"] = "EUC-TW",
        ["EUC_TW"] = "EUC-TW",
        ["BIG5"] = "BIG5",
        ["BIG-5"] = "BIG5",
        ["BIG-FIVE"] = "BIG5",
        ["BIGFIVE"] = "BIG5",
        ["CN-BIG5"] = "BIG5",
        ["CSBIG5"] = "BIG5",
        ["CP950"] = "CP950",
        ["BIG5HKSCS"] = "BIG5HKSCS",
        ["EUC-KR"] = "EUC-KR",
        ["EUCKR"] = "EUC-KR",
        ["CSEUCKR"] = "EUC-KR",
        ["EUC_KR"] = "EUC-KR",
        ["CP949"] = "CP949",
        ["UHC"] = "CP949",
        ["JOHAB"] = "JOHAB",
        ["CP1361"] = "JOHAB",
        ["ISO-2022-KR"] = "ISO-2022-KR",
        ["CSISO2022KR"] = "ISO-2022-KR",
        ["ISO2022KR"] = "ISO-2022-KR",
        ["CHAR"] = "CHAR",
        ["WCHAR_T"] = "WCHAR_T",
}

local function rfc2047(encodedString)
    if not encodedString then
        return
    end
    local decodedString, charset = {}, nil
    -- look for encoding, e.g.,  =?windows-1256?B?VklQIFRv...?=
    for tempCharset, encoding, tempString in string.gmatch(encodedString, "%s-=%?([^?]+)%?([BbQq])%?([^?]+)%?=") do
        if tempCharset and encoding and tempString then
            tempCharset = string.match(tempCharset, "^([^*]+)%*") or tempCharset
            tempCharset = string.upper(tempCharset)
            if charsetAliases[tempCharset] then
                tempCharset = charsetAliases[tempCharset]
            else
                -- Unknown charset
                break
            end
            if charset then
                -- If charset is specified multiple times, each subsequent charset must be the identical to
                -- the first.  There is no way to register meta with multiple charsets.
                if charset ~= tempCharset then
                    break
                end
            else
                -- This is the first charset seen
                charset = tempCharset
            end
            tempString = string.gsub(tempString, "_", " ")
            if encoding == "B" or encoding == "b" then
                tempString = nw.base64Decode(tempString) or tempString
            elseif encoding == "Q" or encoding == "q" then
                tempString = nwll.decodeQuotedPrintable(tempString) or tempString
            end
            table.insert(decodedString, tempString)
        end
    end
    decodedString = (#decodedString > 0 and table.concat(decodedString)) or encodedString
    return decodedString, charset
end

local function extractAddresses(header, type)
    local meta = {}
    local envelopeOriginators
    for target in string.gmatch(header, "[^\"\']+") do
        if string.find(target, "^.*@") then
            for atom in string.gmatch(target, "[^,]+") do
                for address in string.gmatch(atom, "[^<^>]+") do
                    -- trim whitespace
                    local nonWhitespace = string.match(address, "^%s*()")
                    address = (nonWhitespace > #address and "") or (string.match(address, ".*%S", nonWhitespace))
                    if address and #address ~= 0 then
                        local charset
                        if string.find(address, "^.*%?=") then
                            address, charset = rfc2047(address)
                        end
                        if string.find(address, "^.*@") then
                            -- email address
                            if type == "src" then
                                envelopeOriginators = envelopeOriginators or {}
                                table.insert(envelopeOriginators, address)
                            end
                            local type = (options.registerEmailSrcDst.value and type and "email." .. type) or "email"
                            table.insert(meta, {["key"] = type, ["value"] = address, ["charset"] = charset})
                            if not charset then
                                local domainPart = string.match(address, "^.*@(.*)$")
                                if domainPart then
                                    local key
                                    domainPart, key = nwll.determineHostType(domainPart)
                                    if domainPart and key then
                                        if key ~= "alias.host" then
                                            table.insert(meta, {["key"] = "analysis.service", ["value"] = "email address domain is an IP"})
                                        end
                                        if options.registerAddressHosts.value then
                                            table.insert(meta, {["key"] = key, ["value"] = domainPart})
                                        end
                                    end
                                end
                            end
                        else
                            -- comment, probably a name
                            local key = "fullname"
                            if options.registerEmailSrcDst.value and type then
                                if type == "src" then
                                    key = "fullname.src"
                                elseif type == "dst" then
                                    key = "fullname.dst"
                                end
                            end
                            table.insert(meta, {["key"] = key, ["value"] = address, ["charset"] = charset})
                        end
                    end
                end
            end
        elseif #target ~= 0 then
            -- comment, probably a name
            local charset
            if string.find(target, "^.*%?=") then
                target, charset = rfc2047(target)
            end
            if target and #target ~= 0 then
                if string.find(target, "^%s") or string.find(target, "^.*[<>]") then
                    -- trim extraneous characters
                    target = string.match(target, "^%s-<([^>]+)")
                end
                if target and #target ~= 0 then
                    local key = "fullname"
                    if options.registerEmailSrcDst.value and type then
                        if type == "src" then
                            key = "fullname.src"
                        elseif type == "dst" then
                            key = "fullname.dst"
                        end
                    end
                    table.insert(meta, {["key"] = key, ["value"] = target, ["charset"] = charset})
                end
            end
        end
    end
    return meta, envelopeOriginators
end

local mailFunctions = ({
    ["authentication-results"] = 0, -- for identification purposes only, no extraction
    ["bcc"] =
        function(header)
            local meta = extractAddresses(header, "dst")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendto"})
            end
            return meta
        end,
    ["cc"] =
        function(header)
            local meta = extractAddresses(header, "dst")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendto"})
            end
            return meta
        end,
    ["comments"] = 0, -- for identification purposes only, no extraction
    ["content-disposition"] =
        function(header)
            local meta = {}
            local parameters = {}
            for x in string.gmatch(header, "%s-([^;]+)") do
                table.insert(parameters, x)
            end
            for i,j in ipairs(parameters) do
                local attachment = string.match(j, "^.*name=[\"\']?([^\"\']+)")
                if attachment then
                    table.insert(meta, {["key"] = "action", ["value"] = "attach"})
                    local charset
                    attachment, charset = rfc2047(attachment)
                    if attachment then
                        local dir, file, ext = nwll.extractPathElements(attachment)
                        if file then
                            table.insert(meta, {["key"] = "attachment", ["value"] = file, ["charset"] = charset})
                        end
                        if ext then
                            table.insert(meta, {["key"] = "extension", ["value"] = ext, ["charset"] = charset})
                        end
                    end
                end
            end
            return meta
        end,
    ["content-transfer-encoding"] =
        function(header)
            header = (string.find(header, "^%s") and string.match(header, "^%s+(.*)")) or header
            if header == "base64" then
                return {{["key"] = "analysis.service", ["value"] = "base64 email attachment"}}
            end
        end,
    ["content-type"] =
        function(header)
            local meta, boundary = {}, nil
            local parameters, rfc2231 = {}, {}
            for x in string.gmatch(header, "%s*([^;]+)") do
                table.insert(parameters, x)
            end
            for i,j in ipairs(parameters) do
                if i == 1 then
                    table.insert(meta, {["key"] = "content", ["value"] = j})
                else
                    local test
                    test = not options.parseQuoted.value and string.match(j, "^[Bb][Oo][Uu][Nn][Dd][Aa][Rr][Yy] ?= ?[\"']?([^\"']+)")
                    if test then
                        boundary = test
                    else
                        test = string.match(j, "^[Tt][Yy][Pp[Ee] ?= ?\"(.-)\"")
                        if test then
                            table.insert(meta, {["key"] = "content", ["value"] = test})
                        else
                            test = string.match(j, "^[Nn][Aa][Mm][Ee] ?= ?\"(.-)\"")
                            if test then
                                table.insert(meta, {["key"] = "action", ["value"] = "attach"})
                                local attachment, charset = rfc2047(test)
                                if attachment then
                                    local dir, file, ext = nwll.extractPathElements(attachment)
                                    if file then
                                        table.insert(meta, {["key"] = "attachment", ["value"] = file, ["charset"] = charset})
                                    end
                                    if ext then
                                        table.insert(meta, {["key"] = "extension", ["value"] = ext, ["charset"] = charset})
                                    end
                                end
                            else
                                -- collect RFC2231 headers
                                if string.find(j, "^[Ff][Ii][Ll][Ee][Nn][Aa][Mm][Ee]%*") then
                                    rfc2231.filename = rfc2231.filename or {}
                                    local index = string.match(j, "^[Ff][Ii][Ll][Ee][Nn][Aa][Mm][Ee]%*(%d+)") or 0
                                    local atom = string.match(j, "%*%d-%*?=(.*)")
                                    atom = string.gsub(atom, '"', '')
                                    rfc2231.filename[index+1] = atom
                                elseif string.find(j, "^[Nn][Aa][Mm][Ee]%*") then
                                    rfc2231.name = rfc2231.name or {}
                                    local index = string.match(j, "^[Nn][Aa][Mm][Ee]%*(%d+)") or 0
                                    local atom = string.match(j, "%*%d-%*?=(.*)")
                                    if atom then
                                        atom = string.gsub(atom, '"', '')
                                        rfc2231.name[index+1] = atom
                                    end
                                end
                            end
                        end
                    end
                end
            end
            for type, value in pairs(rfc2231) do
                -- register RFC2231 headers
                value = table.concat(value), nil
                local charset, attachment = string.match(value, "^([^']-)'[^']-'(.*)")
                attachment = attachment or value
                table.insert(meta, {["key"] = "action", ["value"] = "attach"})
                local dir, file, ext = nwll.extractPathElements(value)
                if file then
                    table.insert(meta, {["key"] = "attachment", ["value"] = file, ["charset"] = charset})
                end
                if ext then
                    table.insert(meta, {["key"] = "extension", ["value"] = ext, ["charset"] = charset})
                end
            end
            return meta, nil, boundary
        end,
    ["date"] = 0, -- for identification purposes only, no extraction
    ["dkim-signature"] = 0, -- for identification purposes only, no extraction
    ["domainkey-signature"] = 0, -- for identification purposes only, no extraction
    ["envelope-to"] =
        function(header)
            local meta = extractAddresses(header, "dst")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendto"})
            end
            return meta
        end,
    ["from"] =
        function(header)
            local meta = {}
            local extra
            local meta, envelopeOriginators = extractAddresses(header, "src")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendfrom"})
            end
            if envelopeOriginators then
                extra = {["envelopeOriginators"] = envelopeOriginators}
            end
            return meta, extra
        end,
    ["in-reply-to"] =
        function(header)
            local meta = {}
            local extra
            local meta, envelopeOriginators = extractAddresses(header, "src")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendfrom"})
            end
            if envelopeOriginators then
                extra = {["envelopeOriginators"] = envelopeOriginators}
            end
            return meta, extra
        end,
    ["keywords"] = 0, -- for identification purposes only, no extraction
    ["list-archive"] = 0, -- for identification purposes only, no extraction
    ["list-help"] = 0, -- for identification purposes only, no extraction
    ["list-owner"] = 0, -- for identification purposes only, no extraction
    ["list-subscribe"] = 0, -- for identification purposes only, no extraction
    ["list-unsubscribe"] = 0, -- for identification purposes only, no extraction
    ["message-id"] = 0, -- for identification purposes only, no extraction
    ["mime-version"] = 0, -- for identification purposes only, no extraction
    ["precedence"] = 0, -- for identification purposes only, no extraction
    ["received"] =
        function(header)
            local meta = {}
            local MTAfrom = string.match(header, "^(.*)%s?by ") or header
            local MTAby = string.match(header, "^.*by%s(.*)")
            local preHELO, id, id_type, ptr, ptr_type, ip, ip_type, helo, helo_type
            preHELO, helo = string.match(MTAfrom, "^(.*)[Hh][Ee][Ll][Oo]=([%w%.%-%_%:%[%]]+)")
            if preHELO then
                MTAfrom = preHELO
            end
            id   = string.match(MTAfrom, "^%s-[Ff][Rr][Oo][Mm] +([%w%.%-%_%:%[%]]+)")
            ptr  = string.match(MTAfrom, "^[^(]+%(([%w%.%-%_%:]+)")
            ip   = string.match(MTAfrom, "^[^(]+%([^%[]-%[([%w%.%-%_%:]+)%]")
            if id then
                id, id_type = nwll.determineHostType(id)
                if id and id_type then
                    table.insert(meta, {["key"] = id_type, ["value"] = id})
                end
            end
            if ptr then
                ptr, ptr_type = nwll.determineHostType(ptr)
                if ptr and ptr_type then
                    table.insert(meta, {["key"] = ptr_type, ["value"] = ptr})
                end
            end
            if ip then
                ip, ip_type = nwll.determineHostType(ip)
                if ip and ip_type then
                    table.insert(meta, {["key"] = ip_type, ["value"] = ip})
                end
            end
            if helo then
                helo, helo_type = nwll.determineHostType(helo)
                if helo and helo_type then
                    table.insert(meta, {["key"] = helo_type, ["value"] = helo})
                end
            end
            if id and id_type then
                if ptr and ptr_type and id_type == ptr_type and id ~= ptr then
                    table.insert(meta, {["key"] = "analysis.service", ["value"] = "received header hostname mismatch"})
                elseif ip and ip_type and id_type == ip_type and id ~= ip then
                    table.insert(meta, {["key"] = "analysis.service", ["value"] = "received header IP mismatch"})
                end
            end
            if helo and helo_type then
                if ptr and ptr_type and helo_type == ptr_type and helo ~= ptr then
                    table.insert(meta, {["key"] = "analysis.service", ["value"] = "received header hostname mismatch"})
                elseif ip and ip_type and helo_type == ip_type and helo ~= ip then
                    table.insert(meta, {["key"] = "analysis.service", ["value"] = "received header IP mismatch"})
                end
            end
            if MTAby then
                local sender = string.match(MTAby, "^.*[Ee][Nn][Vv][Ee][Ll][Oo][Pp][Ee]%-[Ff][Rr][Oo][Mm]%s-<([^%>]+@[^%>]+)>")
                if sender then
                    local key, charset = (options.registerEmailSrcDst.value and "email.src") or "email", nil
                    sender, charset = rfc2047(sender)
                    if sender then
                        table.insert(meta, {["key"] = key, ["value"] = sender, ["charset"] = charset})
                    end
                end
                local recipient = string.match(MTAby, "^.*[Ff][Oo][Rr]%s-<([^%>]+@[^%>]+)>")
                if recipient then
                    local key, charset = (options.registerEmailSrcDst.value and "email.dst") or "email", nil
                    recipient, charset = rfc2047(sender)
                    if recipient then
                        table.insert(meta, {["key"] = key, ["value"] = recipient, ["charset"] = charset})
                    end
                end
            end
            return meta
        end,
    ["references"] = 0, -- for identification purposes only, no extraction
    ["reply-to"] =
        function(header)
            local meta = {}
            local extra
            local meta, envelopeOriginators = extractAddresses(header, "src")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendfrom"})
            end
            if envelopeOriginators then
                extra = {["envelopeOriginators"] = envelopeOriginators}
            end
            return meta, extra
        end,
    ["resent-bcc"] =
        function(header)
            local meta = extractAddresses(header, "dst")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendto"})
            end
            return meta
        end,
    ["resent-cc"] =
        function(header)
            local meta = extractAddresses(header, "dst")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendto"})
            end
            return meta
        end,
    ["resent-date"] = 0, -- for identification purposes only, no extraction
    ["resent-from"] =
        function(header)
            local meta = {}
            local extra
            local meta, envelopeOriginators = extractAddresses(header, "src")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendfrom"})
            end
            if envelopeOriginators then
                extra = {["envelopeOriginators"] = envelopeOriginators}
            end
            return meta, extra
        end,
    ["resent-message-id"] = 0, -- for identification purposes only, no extraction
    ["resent-sender"] =
        function(header)
            local meta = {}
            local extra
            local meta, envelopeOriginators = extractAddresses(header, "src")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendfrom"})
            end
            if envelopeOriginators then
                extra = {["envelopeOriginators"] = envelopeOriginators}
            end
            return meta, extra
        end,
    ["resent-to"] =
        function(header)
            local meta = extractAddresses(header, "dst")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendto"})
            end
            return meta
        end,
    ["return-path"] =
        function(header)
            local meta = {}
            local extra
            local meta, envelopeOriginators = extractAddresses(header, "src")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendfrom"})
            end
            if envelopeOriginators then
                extra = {["envelopeOriginators"] = envelopeOriginators}
            end
            return meta, extra
        end,
    ["sender"] =
        function(header)
            local meta = {}
            local extra
            local meta, envelopeOriginators = extractAddresses(header, "src")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendfrom"})
            end
            if envelopeOriginators then
                extra = {["envelopeOriginators"] = envelopeOriginators}
            end
            return meta, extra
        end,
    ["subject"] =
        function(header)
            local meta = {}
            local extra
            local subject, charset = rfc2047(header)
            if subject then
                table.insert(meta, {["key"] = "subject", ["value"] = subject, ["charset"] = charset})
                subject = string.lower(subject)
                -- Only want to register these for inbound mail, but in this function we don't
                -- know if it is inbound.  So send it back as "extra" information.
                if string.find(subject, "^re:") then
                    extra = {["sessionVars"] = {["re"] = true}}
                elseif string.find(subject, "^fwd:") then
                    extra = {["sessionVars"] = {["fwd"] = true}}
                else
                    -- only look for phishy subjects if not a Re: or Fwd:
                    for i, j in ipairs(phishySubjects) do
                        if string.find(subject, "^.*" .. j) then
                            extra = {["sessionVars"] = {["subject_phish"] = true}}
                        end
                    end
                end
            end
            return meta, extra
        end,
    ["thread-index"] = 0, -- for identification purposes only, no extraction
    ["to"] =
        function(header)
            local meta = extractAddresses(header, "dst")
            if meta then
                table.insert(meta, 1, {["key"] = "action", ["value"] = "sendto"})
            end
            return meta
        end,
    ["x-cloudmark"] = 0, -- for identification purposes only, no extraction
    ["x-mailer"] =
        function(header)
            local meta = {{["key"] = "client", ["value"] = header}}
            if options.xmailer.value and options.xmailer.value ~= "client" then
                table.insert(meta, {["key"] = options.xmailer.value, ["value"] = header})
            end
            if string.find(header, "^.*[Ee][Xx][Pp][Rr][Ee][Ss][Ss]") then
                table.insert(meta, {["key"] = "analysis.service", ["value"] = "express x-mailer"})
            end
            if string.find(header, "^.*10%.40%.1836") then
                table.insert(meta, {["key"] = "ioc", ["value"] = "Elderwood XMailer Artifact"})
            end
            return meta
        end,
    ["x-original-authentication-results"] = 0, -- for identification purposes only, no extraction
    ["x-originating-ip"] =
        function(header)
            local meta = {}
            for host in string.gmatch(header, "[^, ]+") do
                local key
                host, key = nwll.determineHostType(host)
                if host and key then
                    table.insert(meta, {["key"] = key, ["value"] = host})
                end
            end
            return meta
        end,
})

function mailParser:headerTable(headersBegin, lastHeaderSeen, headersEnd)
    if not lastHeaderSeen then
        return
    end
    if not headersEnd then
        local nPackets, nBytes, nPayloadBytes = nw.getStreamStats()
        headersEnd = nPayloadBytes
    end
    -- want at most 1024 bytes from the last header token match
    headersEnd = (headersEnd - lastHeaderSeen <= 1023 and headersEnd) or lastHeaderSeen + 1023
    if headersEnd - headersBegin > 128000 then
        -- that's still *way* too big to be a set of email headers
        return
    end
    local payload = nw.getPayload(headersBegin, headersEnd)
    local headers, unique = {}, 0
    if payload then
        -- convert the header block into a string
        local headerBlock = payload:tostring()
        payload = nil
        -- construct a table of the individual headers and their values
        local seen = {}
        for line in string.gmatch(headerBlock, "[^\010^\013]+") do
            if #line > 998 then
                -- http://tools.ietf.org/html/rfc5322#section-2.1.1
                -- if we hit a line that exceeds 998 characters it probably isn't an email
                return nil
            end
            local headerType, headerValue = string.match(line, "^(%w[%w_%-]+)%s-:%s-(.*)%s-$")
            if headerType and headerValue then
                headerType = string.lower(headerType)
                table.insert(headers, {["type"] = headerType, ["value"] = headerValue})
                -- keep track of how many unique supported header types we see
                if not seen[headerType] and mailFunctions[headerType] then
                    seen[headerType] = true
                    unique = unique + 1
                end
            elseif #headers > 0 and string.find(line, "^%s") then
                headers[#headers]["value"] = headers[#headers]["value"] .. line
            end
        end
    end
    return headers, unique
end

function mailParser:sessionBegin()
    self.sessionVars = {}
    if self.direction then
        self.sessionVars.direction = self.direction
        self.direction = nil
    end
end

function mailParser:streamBegin()
    self.streamVars = {
        -- ["mailHeadersBegin"],
        -- ["contentHeadersBegin"],
        -- ["mime"] = {
        --     ["outer"]
        --     ["outerMatched"]
        --     ["inner"]
        --     ["innerMatched"]
        -- }
    }
end

function mailParser:checkSrc()
    if self.sessionVars then
        if  self.sessionVars.isMail         and
            self.sessionVars.orgSrc         and
            not self.sessionVars.re         and
            not self.sessionVars.fwd        and
            self.sessionVars.direction == "inbound"
        then
            local orgSrc = self.sessionVars.orgSrc
            if orgSrc then
                orgSrc = string.lower(orgSrc)
                if not commonOrgSources[orgSrc] then
                    nw.createMeta(self.keys["analysis.service"], "uncommon mail source")
                    if self.sessionVars.subject_phish then
                        nw.createMeta(self.keys["analysis.service"], "subject phish")
                    end
                end
            end
        end
    end
end

function mailParser:direction(idx, vlu)
    if version >= 11.3 then
        self.sessionVars.direction = vlu
    else
        self.direction = vlu
    end
end

function mailParser:callPhishing(messageEnd)
    -- Should never get here if phishing is disabled, or don't have messageBegin, or haven't seen an href.
    -- But check anyway...
    if phishingModule and self.streamVars.messageBegin and self.streamVars.href then
        messageEnd = messageEnd or -1
        phishingModule.examine(self.streamVars.messageBegin, messageEnd)
    end
    self.streamVars.href = nil
    self.streamVars.messageBegin = nil
end

function mailParser:mailHeader(token, first, last)
    if not self.streamVars.mime or not self.streamVars.mime.outerMatched and not self.streamVars.contentHeadersBegin then
        if not self.streamVars.mailHeadersBegin then
            self.streamVars.mailHeadersBegin = first
            self.streamVars.lastHeaderSeen = first
            if self.streamVars.href then
                -- href won't be true if don't have messageBegin, and won't have messageBegin if phishing is disabled
                self:callPhishing(first - 1)
            end
        else
            self.streamVars.lastHeaderSeen = first
        end
    end
end

function mailParser:contentHeader(token, first, last)
    if self.streamVars.mailHeadersBegin then
        self.streamVars.lastHeaderSeen = first
    else
        -- Only parse this separately if we've seen an outer mime boundary begin and not an inner mime boundary begin.
        -- Note that if we haven't previously seen a valid block of mail headers, then we can't have seen a boundary.
        if (options.parseQuoted.value or (self.streamVars.mime and self.streamVars.mime.outerMatched and not self.streamVars.mime.innerMatched)) and not self.streamVars.mailHeadersBegin then
            if self.streamVars.contentHeadersBegin then
                self.streamVars.lastHeaderSeen = first
            else
                self.streamVars.contentHeadersBegin = first
                self.streamVars.lastHeaderSeen = first
                if self.streamVars.href then
                    -- href won't be true if don't have messageBegin, and won't have messageBegin if phishing is disabled
                    self:callPhishing(first - 1)
                end
            end
        end
    end
end

function mailParser:href()
    -- won't have messageBegin if phishing is disabled or if isn't an email
    if self.streamVars.messageBegin then
        self.streamVars.href = true
    end
end

function mailParser:endOfHeaders(token, first, last)
    if not (first and last) then
        if self.streamVars.xid then
            self.streamVars.xid:commit()
            self.streamVars.xid = nil
        end
        if self.streamVars.href then
            self:callPhishing()
        end
    end
    if self.streamVars.mailHeadersBegin and self.streamVars.lastHeaderSeen and (self.streamVars.mailHeadersBegin ~= self.streamVars.lastHeaderSeen) then
        local headers, unique = self:headerTable(self.streamVars.mailHeadersBegin, self.streamVars.lastHeaderSeen, (first and first - 1) or nil)
        self.streamVars.mailHeadersBegin, self.streamVars.lastHeaderSeen = nil, nil
        -- only parse a block of headers if we see at least 5 mail headers in that block
        if headers and unique and unique >= 5 then
            local xid
            if transactions then
                xid = self.streamVars.xid
                if xid then
                    xid:commit()
                    self.streamVars.xid = nil
                end
                xid = mailParser:createTransaction()
                self.streamVars.xid = xid
            end
            createMeta(xid, self.keys.content, "mail")
            self.sessionVars.isMail = true
            if self.sessionVars.direction == "inbound" then
                createMeta(xid, self.keys["analysis.service"], "inbound email")
            end
            if phishingModule and last then
                self.streamVars.messageBegin = last + 1
            end
            local state = {}
            for idx, header in ipairs(headers) do
                local headerType = (header.type and string.lower(header.type)) or nil
                if headerType and header.value and mailFunctions[headerType] then
                    if headerType == "to" or headerType == "envelope-to" or "resent-to" then
                        state.sawTo = true
                    elseif headerType == "cc" or headerType == "bcc" then
                        state.sawCC = true
                    end
                    if mailFunctions[headerType] ~= 0 then
                        local meta, extra, boundary = mailFunctions[headerType](header.value)
                        if meta then
                            for metaNum, metaItem in ipairs(meta) do
                                if metaItem.key and metaItem.value then
                                    createMeta(xid, self.keys[metaItem.key], metaItem.value, metaItem.charset)
                                end
                            end
                        end
                        if extra then
                            if extra.sessionVars then
                                for i,j in ipairs(extra.sessionVars) do
                                    for key, value in pairs(j) do
                                        self.sessionVars[key] = value
                                    end
                                end
                            end
                            if extra.streamVars then
                                for i,j in ipairs(extra.streamVars) do
                                    for key, value in pairs(j) do
                                        self.streamVars[key] = value
                                    end
                                end
                            end
                            if extra.envelopeOriginators then
                                state.envelopeOriginators = state.envelopeOriginators or {}
                                for origin_idx, origin_address in ipairs(extra.envelopeOriginators) do
                                    state.envelopeOriginators[origin_address] = true
                                end
                            end
                        end
                        if boundary then
                            -- saw a boundary definition
                            self.streamVars.mime = self.streamVars.mime or {}
                            if not self.streamVars.mime.outer then
                                self.streamVars.mime.outer = "--" .. boundary
                                self.streamVars.mime.outerLength = #boundary
                            elseif self.streamVars.mime.outerMatched and not self.streamVars.mime.inner then
                                self.streamVars.mime.inner = "--" .. boundary
                                self.streamVars.mime.innerLength = #boundary
                            end
                        end
                    end
                    if options.customHeaders.value and options.customHeaders.value[headerType] then
                        createMeta(xid, self.keys[options.customHeaders.value[headerType]], header.value)
                    end
                end
            end
            if not state.sawTo then
                -- no TO: header
                if state.sawCC then
                    createMeta(xid, self.keys["analysis.service"], "email recipients cc/bcc only")
                else
                    -- no CC: header either
                    createMeta(xid, self.keys["analysis.service"], "email missing recipients")
                end
            end
            if state.envelopeOriginators then
                -- If SMTP then compare envelope sender with SMTP sender
                if SMTP_lua == nil then
                    pcall(function()
                        SMTP_lua = require('SMTP_lua')
                        if not (SMTP_lua and type(SMTP_lua) == "table" and SMTP_lua.isSMTP) then
                            SMTP_lua = false
                        end
                    end)
                end
                if SMTP_lua then
                    if SMTP_lua.isSMTP() then
                        local smtpOriginator = SMTP_lua.getOriginator() or "unknown"
                        if not state.envelopeOriginators[smtpOriginator] then
                            createMeta(xid, self.keys["analysis.service"], "smtp forged sender")
                        end
                    end
                end
            end
        end
    end
    if self.streamVars.contentHeadersBegin then
        local headers, unique = self:headerTable(self.streamVars.contentHeadersBegin, self.streamVars.lastHeaderSeen, (first and first - 1) or nil)
        self.streamVars.contentHeadersBegin, self.streamVars.lastHeaderSeen = nil, nil
        if headers and unique and unique > 0 then
            local xid
            if transactions then
                xid = self.streamVars.xid
                if not xid then
                    xid = mailParser:createTransaction()
                    self.streamVars.xid = xid
                end
            end
            for idx, header in ipairs(headers) do
                local headerType = (header.type and string.lower(header.type)) or nil
                if headerType and header.value and mailFunctions[headerType] and mailFunctions[headerType] ~= 0 then
                    local meta, extra, boundary = mailFunctions[headerType](header.value)
                    if meta then
                        for metaNum, metaItem in ipairs(meta) do
                            if metaItem.key and metaItem.value then
                                createMeta(xid, self.keys[metaItem.key], metaItem.value, metaItem.charset)
                            end
                        end
                    end
                    if extra then
                        if extra.sessionVars then
                            for i,j in ipairs(extra.sessionVars) do
                                for key, value in pairs(j) do
                                    self.sessionVars[key] = value
                                end
                            end
                        end
                        if extra.streamVars then
                            for i,j in ipairs(extra.streamVars) do
                                for key, value in pairs(j) do
                                    self.streamVars[key] = value
                                end
                            end
                        end
                    end
                    if boundary then
                        -- saw a boundary definitions
                        self.streamVars.mime = self.streamVars.mime or {}
                        if not self.streamVars.mime.outer then
                            self.streamVars.mime.outer = "--" .. boundary
                            self.streamVars.mime.outerLength = #boundary
                        elseif self.streamVars.mime.outerMatched and not self.streamVars.mime.inner then
                            self.streamVars.mime.inner = "--" .. boundary
                            self.streamVars.mime.innerLength = #boundary
                        end
                    end
                end
                if options.customHeaders.value and options.customHeaders.value[headerType] then
                    createMeta(xid, self.keys[options.customHeaders.value[headerType]], header.value)
                end
            end
        end
    end
    -- Look for mime boundaries, unless:
    --
    --     If first or last are nil then we are at the end of stream so no longer
    --     care about boundaries.
    --
    --     If self.streamVars.mime is nil then either options.parseQuoted is true, or
    --     we haven't seen a boundary definition and so don't care about boundaries.
    --
    --  Per RFC, mime boundaries must be preceded by a double carriage-return/linefeed.
    --  However this may not be adhered to by all MUA's.  So if a boundary isn't seen
    --  after a 0x0d0a0d0a, then look before it as well.
    if self.streamVars.mime and (self.streamVars.mime.outer or self.streamVars.mime.inner) and first and last then
        -- When an outer boundary begin is seen, only attachment headers are
        -- extracted until the outer boundary termination is seen.
        --
        -- When an inner boundary begin is seen, no headers are extracted until
        -- the inner boundary termination is seen - not even attachment headers.
        local mime = self.streamVars.mime
        if mime.outer then
            -- saw outer definition
            if mime.outerMatched then
                -- saw outer begin
                if mime.inner then
                    -- saw inner definition
                    if mime.innerMatched then
                        -- saw inner begin, so look for an inner termination
                        local payload = nw.getPayload(last + 1, last + mime.innerLength + 4)
                        -- first try looking for it after the 0x0d0a0d0a
                        if payload and payload:equal(mime.inner .. "--") then
                            -- inner terminated
                            self.streamVars.mime.innerMatched = false
                            self.streamVars.mime.inner = false
                        else
                            -- then try looking for it before the 0x0d0a0d0a
                            payload = nw.getPayload(first - mime.innerLength - 4, first - 1)
                            if payload and payload:equal(mime.inner .. "--") then
                                -- inner terminated
                                self.streamVars.mime.innerMatched = false
                                self.streamVars.mime.inner = false
                            end
                        end
                    else
                        -- haven't seen inner begin look for inner begin
                        local payload = nw.getPayload(last + 1, last + mime.innerLength + 2)
                        if payload and payload:equal(mime.inner) then
                            -- saw inner begin
                            self.streamVars.mime.innerMatched = true
                        else
                            -- not inner begin, look for outer termination
                            payload = nw.getPayload(last + 1, last + mime.outerLength + 4)
                            -- first try lookking for it after the 0x0d0a0d0a
                            if payload and payload:equal(mime.outer .. "--") then
                                -- outer terminated
                                self.streamVars.mime.outerMatched = false
                                self.streamVars.mime.outer = false
                            else
                                -- then try looking for it before the 0x0d0a0d0a
                                payload = nw.getPayload(first - mime.outerLength - 4, first - 1)
                                if payload and payload:equal(mime.outer .. "--") then
                                    -- outer terminated
                                    self.streamVars.mime.outerMatched = false
                                    self.streamVars.mime.outer = false
                                end
                            end
                        end
                    end
                else
                    -- haven't seen inner definition, so look for outer termination
                    local payload = nw.getPayload(last + 1, last + mime.outerLength + 4)
                    -- first try looking for it after the 0x0d0a0d0a
                    if payload and payload:equal(mime.outer .. "--") then
                        -- outer terminated
                        self.streamVars.mime.outerMatched = false
                        self.streamVars.mime.outer = false
                    else
                        -- then try looking for it before the 0x0d0a0d0a
                        payload = nw.getPayload(first - mime.outerLength - 4, first - 1)
                        if payload and payload:equal(mime.outer .. "--") then
                            -- outer terminated
                            self.streamVars.mime.outerMatched = false
                            self.streamVars.mime.outer = false
                        end
                    end
                end
            else
                -- haven't seen outer begin, so look for outer begin
                local payload = nw.getPayload(last + 1, last + mime.outerLength + 2)
                if payload and payload:equal(mime.outer) then
                    -- saw outer begin
                    self.streamVars.mime.outerMatched = true
                end
            end
        end
    end
end

function mailParser:orgSrc(idx, vlu)
    -- TODO use the new GeoIP API instead
    if self.sessionVars then
        self.sessionVars.orgSrc = vlu
        if version < 11.3 then
            self:checkSrc()
            -- This callback occurs after session end, since we're here may as well do this too
            self.sessionVars = nil
            self.streamVars = nil
        end
    end
end

function mailParser:sessionEnd()
    self:checkSrc()
end

local callbacks = {
    -- initialize
    [nwevents.OnSessionBegin] = mailParser.sessionBegin,
    [nwevents.OnStreamBegin] = mailParser.streamBegin,
    -- callbacks
    [nwlanguagekey.create("direction")] = mailParser.direction, -- occurs before session begin
    [nwlanguagekey.create("org.src")] = mailParser.orgSrc,      -- occurs after session end
    -- mail header tokens
    ["^Authentication-Results:"] = mailParser.mailHeader,
    ["^bcc:"] = mailParser.mailHeader,
    ["^Bcc:"] = mailParser.mailHeader,
    ["^BCC:"] = mailParser.mailHeader,
    ["^cc:"] = mailParser.mailHeader,
    ["^Cc:"] = mailParser.mailHeader,
    ["^CC:"] = mailParser.mailHeader,
    ["^comments:"] = mailParser.mailHeader,
    ["^Comments:"] = mailParser.mailHeader,
    ["^COMMENTS:"] = mailParser.mailHeader,
    ["^content-transfer-encoding:"] = mailParser.mailHeader,
    ["^Content-transfer-encoding:"] = mailParser.mailHeader,
    ["^Content-Transfer-Encoding:"] = mailParser.mailHeader,
    ["^CONTENT-TRANSFER-ENCODING:"] = mailParser.mailHeader,
    ["^date:"] = mailParser.mailHeader,
    ["^Date:"] = mailParser.mailHeader,
    ["^DATE:"] = mailParser.mailHeader,
    ["^DKIM-Signature:"] = mailParser.mailHeader,
    ["^DomainKey-Signature:"] = mailParser.mailHeader,
    ["^envelope-to:"] = mailParser.mailHeader,
    ["^Envelope-to:"] = mailParser.mailHeader,
    ["^Envelope-To:"] = mailParser.mailHeader,
    ["^ENVELOPE-TO:"] = mailParser.mailHeader,
    ["^from:"] = mailParser.mailHeader,
    ["^From:"] = mailParser.mailHeader,
    ["^FROM:"] = mailParser.mailHeader,
    ["^in-reply-to:"] = mailParser.mailHeader,
    ["^In-reply-to:"] = mailParser.mailHeader,
    ["^In-Reply-To:"] = mailParser.mailHeader,
    ["^IN-REPLY-TO:"] = mailParser.mailHeader,
    ["^keywords:"] = mailParser.mailHeader,
    ["^Keywords:"] = mailParser.mailHeader,
    ["^KEYWORDS:"] = mailParser.mailHeader,
    ["^List-Archive:"] = mailParser.mailHeader,
    ["^List-Help:"] = mailParser.mailHeader,
    ["^List-Owner:"] = mailParser.mailHeader,
    ["^List-Subscribe:"] = mailParser.mailHeader,
    ["^List-Unsubscribe:"] = mailParser.mailHeader,
    ["^message-id:"] = mailParser.mailHeader,
    ["^Message-Id:"] = mailParser.mailHeader,
    ["^Message-ID:"] = mailParser.mailHeader,
    ["^MESSAGE-ID:"] = mailParser.mailHeader,
    ["^mime-version:"] = mailParser.mailHeader,
    ["^Mime-version:"] = mailParser.mailHeader,
    ["^Mime-Version:"] = mailParser.mailHeader,
    ["^MIME-version:"] = mailParser.mailHeader,
    ["^MIME-VERSION:"] = mailParser.mailHeader,
    ["^precedence:"] = mailParser.mailHeader,
    ["^Precedence:"] = mailParser.mailHeader,
    ["^PRECEDENCE:"] = mailParser.mailHeader,
    ["^received:"] = mailParser.mailHeader,
    ["^Received:"] = mailParser.mailHeader,
    ["^RECEIVED:"] = mailParser.mailHeader,
    ["^references:"] = mailParser.mailHeader,
    ["^References:"] = mailParser.mailHeader,
    ["^REFERENCES:"] = mailParser.mailHeader,
    ["^reply-to:"] = mailParser.mailHeader,
    ["^Reply-to:"] = mailParser.mailHeader,
    ["^Reply-To:"] = mailParser.mailHeader,
    ["^REPLY-TO:"] = mailParser.mailHeader,
    ["^return-path:"] = mailParser.mailHeader,
    ["^Return-path:"] = mailParser.mailHeader,
    ["^Return-Path:"] = mailParser.mailHeader,
    ["^RETURN-PATH:"] = mailParser.mailHeader,
    ["^sender:"] = mailParser.mailHeader,
    ["^Sender:"] = mailParser.mailHeader,
    ["^SENDER:"] = mailParser.mailHeader,
    ["^subject:"] = mailParser.mailHeader,
    ["^Subject:"] = mailParser.mailHeader,
    ["^SUBJECT:"] = mailParser.mailHeader,
    ["^to:"] = mailParser.mailHeader,
    ["^To:"] = mailParser.mailHeader,
    ["^TO:"] = mailParser.mailHeader,
    ["^X-Cloudmark-"] = mailParser.mailHeader,
    ["^x-mailer:"] = mailParser.mailHeader,
    ["^X-mailer:"] = mailParser.mailHeader,
    ["^X-Mailer:"] = mailParser.mailHeader,
    ["^X-MAILER:"] = mailParser.mailHeader,
    ["^X-Original-Authentication-Results:"] = mailParser.mailHeader,
    ["^x-originating-ip:"] = mailParser.mailHeader,
    ["^X-originating-IP:"] = mailParser.mailHeader,
    ["^X-Originating-IP:"] = mailParser.mailHeader,
    ["^X-ORIGINATING-IP:"] = mailParser.mailHeader,
    -- attachment tokens
    ["^content-disposition:"] = mailParser.contentHeader,
    ["^Content-disposition:"] = mailParser.contentHeader,
    ["^Content-Disposition:"] = mailParser.contentHeader,
    ["^CONTENT-DISPOSITION:"] = mailParser.contentHeader,
    ["^content-transfer-encoding:"] = mailParser.contentHeader,
    ["^Content-transfer-encoding:"] = mailParser.contentHeader,
    ["^Content-Transfer-Encoding:"] = mailParser.contentHeader,
    ["^CONTENT-TRANSFER-ENCODING:"] = mailParser.contentHeader,
    ["^content-type:"] = mailParser.contentHeader,
    ["^Content-type:"] = mailParser.contentHeader,
    ["^Content-Type:"] = mailParser.contentHeader,
    ["^CONTENT-TYPE:"] = mailParser.contentHeader,
    -- phishing detection
    ["HREF"] = mailParser.href,
    ["Href"] = mailParser.href,
    ["href"] = mailParser.href,
    -- register meta
    ["\013\010\013\010"] = mailParser.endOfHeaders,
    ["\013\010.\013\010"] = mailParser.endOfHeaders,  -- SMTP end-of-message (failsafe)
    [nwevents.OnStreamEnd] = mailParser.endOfHeaders,
}

if version >= 11.3 then
    callbacks[nwevents.OnSessionEnd] = mailParser.sessionEnd
end

mailParser:setCallbacks(callbacks)

return summary