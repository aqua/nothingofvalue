# nothingofvalue - a webserver of least possible value

Nothing of value is here.

A self-contained webserver which strives to be of as little use as possible,
as a musing on the modern zombie internet, where any webserver sees a constant
background noise of malicious traffic punctuated by aggressive scrapers.

Serves a single homepage of no great value, a /robots.txt forbidding all
robotic crawls other than that homepage, and on all other possible URLs serves
content of the least productive value possible, while keeping locally-consumed
resources modest.

Not an infinitely-recursrive content tarpit (I wrote
[one of those](https://devin.com/sugarplum/) too for spambots many years ago if
you need one, and there are many more now aimed at poisoning abusive AIs);
nothing the server offers encourages more requests, but it does aim to respond
to every request in the least helpful way possible.

Notable valueless offerings include decompression bombs for common image
codecs and transport encodings, exponentially self-expanding markup language
documents, made-up credentials, and similar.

Usage: 

```
  go run main/main.go --listen=localhost:8080
```

Demo:

*  [Harmless homepage](https://sev2.com/)
*  [robots.txt](https://sev2.com/robots.txt)
*  [.git/config](https://sev2.com/foo/.git/config)
*  [VSCode STFP config](https://sev2.com/bar/ftp-sync.json)
*  [AWS Credentials](https://sev2.com/baz/.AWS/credentials)
*  [Node .env](https://sev2.com/something/.env)
*  [PHP .ini](https://sev2.com/something/php.ini)
*  [Random path of no meaning](https://sev2.com/something/unrecognized)
*  [Arbitrary JSON](https://sev2.com/arbitrary.json)
*  More-hostile requests you can make; your actual results will vary
   depending on your browser's supported transport encodings:
   *  .zip
   *  .webp
   *  .png
   *  .jpeg
   *  .yaml
   *  wlwmanifest.xml
