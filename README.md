# modsecurityaudit2timeline
Convert modsecurity audit logs to CSV for analysis

This program takes a list of modsecurity audit files and outputs a CSV file.
I've found it useful for incident response and general analysis of modsecurity audit files.
Currently the program is capable of parsing sections a, b, c, f, h and k of the modsecurity audit files.
For each section of the audit file, I've implemented parsers which will extract useful information.
Some useful information that gets extracted include:
* Request headers
* Cookies
* Request parameters (POST and GET)
* Modsecurity alert details

I've designed the program to be easy to extend. I'd like incorporate this into [plaso](https://github.com/log2timeline/plaso) in the future.
