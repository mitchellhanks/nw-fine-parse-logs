module("TLS_lua_options")
-- 2019.12.04.1

function overwriteService()
    --[[
        "Overwrite Service": default false
        
            Default behavior is that if another parser has identified a session with service
            other than SSL, then this parser will not overwrite the service meta.
            
            If this option is enabled, then the parser will identify all sessions containing
            SSL as SSL even if a session has been identified by another parser as another
            service.
    --]]
    return false
end

function portsOnly()
    --[[    
        "Ports Only": default false
        
            Default behavior is port-agnostic - the parser looks for all SSL/TLS sessions
            regardless of which ports a session uses.  This allows identification of encrypted
            sessions on unexpected and/or non-standard ports.
            
            If this option is enabled, then the parser will only look for SSL/TLS sessions
            using the configured ports.  Sessions on other ports will not be identified
            as SSL/TLS.  This may improve performance, at a cost of decreased visibility.
            
            Note that a session on a configured port that is not SSL/TLS will still not be
            identified as SSL/TLS.  In other words, the parser doesn't assume that all sessions
            on configured ports are SSL/TLS.
            
            This option accepts a comma-separated list of port on which to look for SSL/TLS, e.g.,
            
                return "443,8088,9001"
    --]]
    return false
end