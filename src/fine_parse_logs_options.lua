module('fine_parse_logs_options')

--[=[   SEARCH CONDITIONS FOR FINE_PARSE_LOGS.LUA

		Create a separate entry for each callback meta value/pattern combination.  

		VERSION

			1.0

		NOTES
			
			This is (part of) a community parser, found on GitHub:  https://github.com/mitchellhanks/nw-fine-parse-logs

			See the project README on GitHub for instructions, downloads and version history.

			CAUTION: See project README regarding potential negative impact to performance in using this parser.

		USAGE

			{
				callbackval="<string>",
				metakey="<string>",
				pattern="<string>",
				isarray=<integer>,
				arraydelim="<string>"
			},
		
			Where:
				callbackval 	:	[REQUIRED] value that must exist in the meta callback in order to initiate the pattern search
				metakey 		: 	[REQUIRED] meta key name to use for registering value upon match
				pattern 		: 	[REQUIRED] Lua pattern to use for searching the raw log.  Will extract the first capture group.  
												For more info, see: https://github.com/mitchellhanks/nw-fine-parse-logs
				isarray 		: 	[Optional] Default(0:false) (1:true) If set to 1 then the extracted value will be split using the 
									delimiter and each value registered separately to the same meta key
				arraydelim 		: 	[Optional] Required if "isarray" is set to 1.  Delimiter used to split the value array.
		
		
		EXAMPLE
			{
				callbackval="rsa_netwitness_audit",
				metakey="context",
				pattern="\"agent\":\"(.-)\""
			},
			{
				callbackval="rsa_netwitness_audit",
				metakey="context",
				pattern="agentIds\\=%[(.-)]",
				isarray=1,
				arraydelim=", "
			},

	--]=]

function get_search_conditions()
	return {
		{callbackkey="device.type", callbackval="rsa_netwitness_audit", metakey="agent.id", pattern="\"agent\":\"(.-)\""},
		{callbackkey="device.type", callbackval="rsa_netwitness_audit", metakey="agent.id", pattern="agentIds\\=%[(.-)]", isarray=1, arraydelim=", "},
		{callbackkey="event.name", callbackval="rsa_netwitness_audit", metakey="agent.id", pattern="sandwich\\=%[(.-)]"},
	}
end