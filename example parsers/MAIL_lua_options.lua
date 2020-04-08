module("MAIL_lua_options")
-- 2018.09.17.1

function registerEmailSrcDst()
    --[[
        "Register email.src and email.dst": default false

            Whether to register email address meta using the index keys
            "email.src" and "email.dst".

            If set to FALSE, all email address meta is registered with
            the index key "email".

            If set to TRUE:

             - Originating email addresses will be registered with the index
               key "email.src"

             - Recipient email addresses will be registered with the index
               key "email.dst"
               
            Modifying this option requires a service restart to take effect - a
            simple parser reload is insufficient.
    --]]
    return false
end

function parseQuoted()
    --[[
        "Parse Quoted Messages" : default false
            
            If set to false (default) then meta will not be extracted
            from headers which are contained within an email message
            (i.e., from a quoted message).
            
            If set to true, then headers from quoted messages will be
            parsed.
    --]]
    return false
end

function registerAddressHosts()
    --[[
        "Register Address Hosts" : default false

            Whether to register the host portion of email addresses as meta.

            The key used to register will be alias.host, alias.ip, or
            alias.ipv6 as appropriate.
    --]]
    return false
end

function parseReceived()
    --[[
        "Parse Received headers" : default true

            Whether to register meta from Received: headers.

            Many MTAs put all sorts of badly formatted information into
            "Received:" headers.  Most likely this will manifest as alias.host
            meta that isn't a hostname.

            If this is problematic in your environment, disable parsing of
            Received: headers by setting this option to false.
    --]]
    return true
end

function customHeaders()
    --[[
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
    --]]
    return {
        --["x-mailer"] = "client",
    }
end
