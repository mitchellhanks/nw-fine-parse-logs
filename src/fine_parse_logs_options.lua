module('fine_parse_logs_options')

--[=[   SEARCH CONDITIONS FOR FINE_PARSE_LOGS.LUA

		Create a separate entry for each callback meta value/pattern combination.

		HISTORY

			1.0 - Initial version
			1.1 - Required for script v1.1 - Added callbackkey as a required parameter; added Lua pattern matching for meta callback value

		NOTES
			
			This is (part of) a community parser, found on GitHub:  https://github.com/mitchellhanks/nw-fine-parse-logs

			See the project README on GitHub for instructions, downloads and version history.

			CAUTION: See project README regarding potential negative impact to performance in using this parser.

		UPGRADING

			When upgrading the main parser, check the release notes at https://github.com/mitchellhanks/nw-fine-parse-logs/releases
			to determine if a new _options file is required.  If so, copy and paste your entries below into the new file and make adjustments.
			For example, add any new required fields.  Check "Troubleshooting" in the GitHub README for more info.

		USAGE

			{
				callbackkey="<string>",
				callbackval="<string>",
				metakey="<string>",
				pattern="<string>",
				isarray=<integer>,
				arraydelim="<string>"
			},
		
			Where:
				callbackkey 	:	[REQUIRED] meta key that must exist in the meta callback in order to initiate the pattern search
				callbackval 	:	[REQUIRED] meta value (or Lua pattern) that must exist in the meta callback in order to initiate the pattern search
				metakey 		: 	[REQUIRED] meta key name to use for registering value upon match
				pattern 		: 	[REQUIRED] Lua pattern to use for searching the raw log.  Will extract the first capture group.  
												For more info, see: https://github.com/mitchellhanks/nw-fine-parse-logs
				isarray 		: 	[Optional] Default(0:false) (1:true) If set to 1 then the extracted value will be split using the 
									delimiter and each value registered separately to the same meta key
				arraydelim 		: 	[Optional] Required if "isarray" is set to 1.  Delimiter used to split the value array.
		
		
		EXAMPLE
			{
				callbackkey="action",
				callbackval="scan",
				metakey="context",
				pattern="agentIds\\=%[(.-)]",
				isarray=1,
				arraydelim=", "
			},
		
		TIP: Use Lua patterns for "fuzzy" matching the meta callback value.  e.g. To scan the raw log any time the 
		meta key "event.name" is present (regardless of value) and register the extracted value to the "context" meta key
			{
				callbackkey="event.name",
				callbackval=".*",
				metakey="context",
				pattern="query\=\"(.-)\""
			},

	--]=]

function get_search_conditions()
	return {
		{callbackkey="event.name", callbackval=".*", metakey="agent.id", pattern="\"agent\":\"(.-)\""},
		{callbackkey="event.name", callbackval=".*", metakey="agent.id", pattern="agentIds\\=%[(.-)]", isarray=1, arraydelim=", "},
		{callbackkey="event.name", callbackval=".*", metakey="query", pattern="query\\=\"(.-)\""},
		{callbackkey="event.name", callbackval=".*", metakey="query", pattern="params={(\"select\":.-)}"},
	}
end