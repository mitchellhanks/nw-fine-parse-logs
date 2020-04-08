# lua-parser-template

Template and examples of Lua parsers for RSA NetWitness platform.

## About Lua Parsers in RSA NetWitness Platform

Lua parsers are typically used for parsing network (packet) data, however they can be used for log data as well.

The best reference for building Lua parsers in NetWitness is [A Treatise on Writing Packet Parsers for the RSA NetWitness Platform][], by William (Bill) Motley at RSA.

> CAUTION: Please read Bill's book before attempting to create and run your parser in production.  A poorly-written parser can cause a **severe** performance impact!

## How to use this Template

Please **fork** this repo to your GitHub account or click `Use This Template` in the GitHub UI.  If you plan to share your parser with the community, the fork relationship will help RSA to track your progress as you update your repo.  If you prefer not to share it, you can just clone the repo or download it using the GitHub download button above.

You will find examples of "Live" lua parsers produced by RSA in the `/examples` folder.  Some of them are fairly complex, but your parser does not have to be.  The `template.lua` file is a basic skeleton of a simple parser.  Feel free to experiment (in a lab!) and make it your own.

As you will see in the `template.lua` and the example parsers, it is a good idea to keep a version history of your parser.  You can do this within the parser itself or in your GitHub repo.  You can format this however you like, however there are a few tips we suggest:

* Try to include the compatible NetWitness product versions that work with your parser, if applicable.
* There's no need to include EVERY commit in your version history.  Only the versions that are considered "releases".
* DO NOT include your email address in your parser or in your GitHub repo as this will likely cause you to be spammed.

> NOTE: RSA is not responsible for support of community content.

## More Info

See the [RSA NetWitness Platform Integrations][] space on the RSA community site for questions, discussions and more how-to information on building your own content.

## Version History

| Release | Date       | Changes |
| ------- | ---------- | ------- |
| v0.2    | 7-Mar-2020 | beta    |

## License

This project is licensed under the Apache 2.0 license - see the [LICENSE.md][] file for details

## Acknowledgements

All of the code and instructions here are provided by Bill Motley, the man who literally wrote the book on Lua parsing in NetWitness.

[A Treatise on Writing Packet Parsers for the RSA NetWitness Platform]: https://community.rsa.com/docs/DOC-41370
[RSA Link Content Catalog]: https://community.rsa.com/community/products/netwitness/integrations/catalog
[LICENSE.md]: https://github.com/netwitness/lua-parser-template/blob/master/LICENSE
[RSA NetWitness Platform Integrations]: https://community.rsa.com/community/products/netwitness/integrations
