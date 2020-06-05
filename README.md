# nw-fine-parse-logs

A Lua parser for [RSA NetWitness Platform] which will extract meta from logs using Lua patterns.  

## Downloads

See **[releases]** for downloads and version history.

> NOTE: Unless otherwise noted in the release notes, you don't need to deploy the options file a second time.  If you do need to re-deploy the options file, please be sure to back up your configurations.

## How it Works

This parser works by using [Lua patterns] to extract desired values to meta.  This is mainly useful when there is already a parser which handles most of the parsing, but you want to extract separate values found within a single meta key (i.e. "fine parsing").

The parser comes with an "options" lua file where you will configure the patterns to use, the meta key(s) to register with the extracted values and the meta key value that will trigger the parser.

The parser was designed so that you don't really have to know how to write lua parsers in order to use it.  However if you would like to learn more about lua in NetWitness, see [Parsers: A Treatise on Writing Packet Parsers for the RSA NetWitness Platform].

Let's look at each of the main components a little closer.  First, the parser will look for any of the meta keys defined in the options file to be present in the session (`event.name` for instance).

> NOTE: To minimize performance impact of this parser, avoid meta keys that are present in all/most logs (for instance `device.type`) but one that is present in the logs you are insterested in fine parsing.

When the defined meta key is present, the parser will take its value and compare it to the list of values defined in `fine_parse_logs_options.lua` for that meta key name.  If there is a match, it will execute the defined lua pattern against the entire raw log.  If the pattern matches the log, it will extract the value and assign it to the defined meta key.

## Deployment

There are several ways to deploy custom Lua parsers.  The easiest way currently is to use the [Resource Package Deployment Wizard] found within the Live UI<sup>[1](#livenavigation)</sup>.  The ZIP files found below in the [versions](#versions) table are packaged so that they can be deployed using this method.

> IMPORTANT: When first installing the parser, you will need **BOTH** the `fine_parse_logs.lua` file **AND** the `fine_parse_logs_options.lua` file.  However, DO NOT re-deploy the options file after you have configured it or else your configurations will be overwritten with the defaults.  If you need to upgrade the options file, make sure to backup your settings first!

## Configuring the Options File

For each pattern you wish to use, create a JSON-formatted entry in `fine_parse_logs_options.lua` using the following structure:

> This has to be placed inside the `get_search_conditions()` function

```lua
{
    callbackkey="<string>",
    callbackval="<string>",
    metakey="<string>",
    pattern="<string>",
    isarray=<integer>,
    arraydelim="<string>"
},
```

### Where

| Parameter   | Required              | Description                                                                                                                                                                |
| ----------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| callbackkey | yes                   | meta key that must exist in the meta callback in order to initiate the parser                                                                                              |
| callbackval | yes                   | value that must exist in the meta callback in order to initiate the pattern search (accepts Lua patterns)                                                                  |
| metakey     | yes                   | meta key name to use for registering value upon match                                                                                                                      |
| pattern     | yes                   | Lua pattern to use for searching the raw log.  Will extract the first capture group.                                                                                       |
| isarray     | no                    | (0=false \[Default\]) (1=true) If set to 1 then the extracted value will be split using the value of `delimiter` and each value registered separately to the same meta key |
| arraydelim  | only if `isarray` = 1 | Delimiter used to split the value array.                                                                                                                                   |

### Example

Let's say you want to extract the `agent.id` values from the below log snippet (abbreviated):

```log
... params={"agent":"070BF435-8BFC-42B5-22DC-AB89837A8F50","policy revision":"-8613798722556454633"} ...
... arguments=[ScanCommand(agentIds\=[9D24B9F8-A9A9-D622-D307-C74358066390, A16D103F-96A8-49DB-0C95-96A1A323C2F2, 02958B9B-78B3-1A9B-21AA-B6FF78ACD0FE], ...
... arguments=[ScanCommand(agentIds\=[03090AEE-6E3B-8221-8143-75EB18BE72B5], scanCommandType\=QUICK_SCAN)] ...
```

Assuming these logs are already parsed by NetWitness with the following meta `event.name="scan"`, then you can configure the following pattern entries to extract the `agent.id` values which might not have been parsed out already:

```lua
{callbackkey="event.name", callbackval="scan", metakey="agent.id", pattern="\"agent\":\"(.-)\""},
{callbackkey="event.name", callbackval="scan", metakey="agent.id", pattern="agentIds\\=%[(.-)]", isarray=1, arraydelim=", "},
```

Lua patterns may also be used in the `callbackval`.  Or if you don't care what value is in `event.name` and you want the pattern search to run any time this key is simply present, you can use Lua patterns to achieve this (for instance `.*`).

```lua
{callbackkey="event.name", callbackval=".*", metakey="agent.id", pattern="\"agent\":\"(.-)\""},
{callbackkey="event.name", callbackval=".*", metakey="agent.id", pattern="agentIds\\=%[(.-)]", isarray=1, arraydelim=", "},
```

Each pattern must have **exactly** one "capture group", defined by the pattern found within the parentheses `(xyz)`.

If your pattern exists multiple times within the raw log, then this parser will extract each match and register it to the same defined meta key.  If this is the case, it's a good idea (not required) to use a meta key that is defined as a string array type under your ESA Rules settings.

If the value you are extracting contains a delimited list of values you can use the "isarray" and "arraydelim" properties to cause the parser to extract each value and register it to the defined meta key separately.

## Troubleshooting

### Watch the logs

You can test the configuration of your options file by watching the logs for any errors.  Try running the following command from an SSH session in your Log Decoder while you load the parser or when the relevant logs are consumed:

```bash
tail -f /var/log/messages | grep -i lua
```

If your options file has errors, the log will specify where the error was found in your configuration.

### Upgrades

The parser will be upgraded from time to time and often will not require any changes to the `fine_parse_logs_options.lua` file.  If there IS a required change it will be notes under [releases].  The only thing to back up is your entries in the options file.  You may have to update them to add new required parameters or other enhancements.

## A Word of Caution

Using this parser can NEGATIVELY IMPACT PERFORMANCE, although the performance impact will depend on the volume of logs which match your options parameters.  In most cases, the impact will be negligible-to-minor, but please do some testing before leaving this parser running in production.

## More Info

For more info on writing Lua parsers for NetWitness, see: [Parsers: A Treatise on Writing Packet Parsers for the RSA NetWitness Platform]

For general help with custom parsers, you can try the [NetWitness community on integrations].

Here are some good references for understanding Lua patterns:

* [Official lua reference]
* [Lua Patterns Tutorial]

## To Do

1. Test and document using transient meta to trigger the parser

## License

This project is licensed under the Apache 2.0 license - see the [LICENSE.md] file for details

## Footnotes

<a name="livenavigation">1</a>: The navigation menu might be different on various versions, however the steps in the deployment wizard should be the same or similar.

<!-- REFERENCE LINKS -->
[Parsers: A Treatise on Writing Packet Parsers for the RSA NetWitness Platform]: https://community.rsa.com/docs/DOC-41370
[LICENSE.md]: https://github.com/mitchellhanks/nw-fine-parse-logs/blob/master/LICENSE
[Lua patterns]: https://www.lua.org/pil/20.2.html
[Resource Package Deployment Wizard]: https://community.rsa.com/docs/DOC-74318
[RSA NetWitness Platform]: https://community.rsa.com/community/products/netwitness
[NetWitness community on integrations]: https://community.rsa.com/community/products/netwitness/integrations
[Lua Patterns Tutorial]: http://lua-users.org/wiki/PatternsTutorial
[Official lua reference]: https://www.lua.org/pil/20.2.html
[releases]: https://github.com/mitchellhanks/nw-fine-parse-logs/releases