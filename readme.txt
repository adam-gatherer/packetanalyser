Hello!

pcap_analyser.py
Written by Adam Gatherer
Nov/Dec 2021

To run this script, use it at the command line with a pcap file as an argument.
If no pcap file argument is given (or an invalid filename used), the script
will search the current working directory for a pcap file and use the first one
it finds. No argument given and no file found? It just won't run in that case!

Script is incomplete and does not perform all required functions. To be added
in the future: traffic over time analysis and graph production, better
exception handling, maybe reduce size of main(), add option to output data to
files instead of displaying on screen etc.



The following third party modules/libraries/packages are used in this script:

Geo2ip
https://github.com/maxmind/GeoIP2-python

Simplekml
https://github.com/eisoldt/simplekml

Prettytable
https://github.com/jazzband/prettytable

Dpkt
https://github.com/kbandla/dpkt
