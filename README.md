tinyIDS
====================

Technical details
---------------------
This is an example of how you can use pcap libraries in python to build a POC IDS.
The project is based on dpkt in python 2.7 and is only proof of concept. Development will continue but the most important part of the project is to spawn
new ideas. The primary use case is penetration testing when sniffing traffic. 

## Rules

Rules are available in the folder rules/
During startup this folder is searched for .json files which then are parsed. All rules are based on json to simpilfy the rule creating process.
Rules can be either data matching rules or regular expression rules. If the rule is data matching you can match on several types of data in one rule.
tinyIDS only loads the rule when starting. Any changes to the rules mean you have to restart it.

This is an example of a regular expression rule:

````json
{
    "app": "http",
    "block": "no",
    "data": "5[1-5][0-9]{14}", <- Regular expression to match on
    "dport": 80,
    "enabled": "no",
    "file_name": "./rules/mastercard.json",
    "proto": "tcp",
    "regexp": "yes",
    "rule_id": 10,
    "rule_name": "Mastercard Credit Card Rule",
    "sport": 80
}
````

This is an example of a data matching rule with multiple data matching. The data is separated with a "|" as seen below.

````json
{
    "app": "http",
    "block": "yes",
    "data": "2532372B4F522B|53454C45435420|404076657273696F6E|53454C454354202A",
    "dport": 80,
    "enabled": "yes",
    "file_name": "./rules/sqli.json",
    "proto": "tcp",
    "regexp": "no",
    "rule_id": 6,
    "rule_name": "SQL Injection",
    "sport": 80
}
```

There are a couple of examples in the rules/ directory. The program will write an error to the screen if there is an issue in any rule. Example:

```
"Rule error. Please check rule ./rules/russiadns.json"
```


## CLI Interface

```
tinyIDS CLI
A small, but flexible IDS. Keeping you paranoid since 2014.
===========================================================
Command            Description
-----------------  ----------------------------------------------
list known ip      List all known IPs in cache
stat known ip      Show number of known IPs in cache
stat ports         List statistics per port
show log           Show log file
show alerts        Show all IDS alerts in the log file
show alert <id>    Show information regarding a specific alert id
show threats       Show all threat feed alerts in the log file
show rules         List all rules
disable rule       Disable a rule
enable rule <id>   Enable a rule
show filters       Show filters
add filter         Add filter
del filter         Delete a filter
mod filter         Modify a filter
add threat url     Add a url to auto download
del threat url     Delete a auto download url
list threat urls   Show urls that are being auto downloaded
list threat ip     List all IPs in threat list
stat threat ip     Show number of IPs in threat list
clear threat list  Clear the threat ip list
search threat ip   Search for IP in threat list
add threat ip      Add new IP to threat list
del threat ip      Delete IP in threat list
dl threat list     Download threat list
set update time    Change the update time of the feed updates
get update time    View the current update time
date               Show current time
clear log          Clear tinyids.log file
quit/exit          Quit tinyIDS
==================================================
```

## IP Feeds

You can supply tinyIDS with ip feeds. For instance if you have a .txt file with known bad IP's you can place it in the feeds folder. The format has to be the same as the example file in the feeds folder.
All alerts are written to the tinyids.log file.

It is also possible via CLI to download a threat feed url and then add it to the IDS without restart.
Use the CLI option 'dl threat list'

## How it works

The way it matches is that it converts data to hex and then do a contains on the entire packet. If any packet triggers a log message is written to the screen and saved to a mysql/mariadb database.
To create more rules simply copy a rule file and convert any string data such as ip to hex and put it in the "data" field of the rule.

Right now matches are only made on the data part in the packet, however it can be expanded quite easily. It can also unpack gzip data in http packets to match on data that is gzipped.

If you want to expand how it matches signatures you can edit the main.py file and do more matches on ports etc.
For instance in  http traffic the source port is 80 and destination port 80 depending on which way the traffic is going.

## Installation & requirements

tinyIDS is developed on Kali Linux using python 2.7. It requires some external libraries and they are all documented in the install script.
Currently it is only tested on Kali Linux, Debian 7.7 and CentOS 7.0. To install on Kali:

```
1. chmod +x INSTALL-KALI.sh
2. ./INSTALL-KALI.sh
3. python main.py
```

And yes, it is also tested and working on a Raspberry Pi.

A simple use case is to run a tap on a network port to inspect traffic. For debian you can configure a interface to be promiscious by editing the file
 /etc/network/interfaces

```
auto eth0
iface eth0 inet manual
        up ifconfig eth0 promisc up
        down ifconfig eth0 promisc down
```

## Configuration file
Make sure you check out the tinyids.cfg file for settings and configuration parameters. Parameters such as 'trafficbuffer' should be set as you prefer.
There are also debug commands where you can get more information on system performance

## Database
tinyIDS uses mongodb to store alerts, filters, traffic exclusions etc. 

## Traffic Exclusions
It is possible to exclude traffic. However, only on TCP and UDP traffic. You can add entries to the database table excluded_traffic. The example below filters TCP traffic and port 22, 443.
To exclude traffic you have to restart tinyIDS. Currently this cannot be done via CLI.
``` mongodb
use tinyids
db.excluded_traffic.insert( { 'date' : new ISODate(), "proto" : 6 , port : 443 } )
db.excluded_traffic.insert( { 'date' : new ISODate(), "proto" : 6 , port : 22 } )
```
It will be visibile in the log when you start tinyIDS. For example:
```
2015-02-01 20:28:40,937 Excluding all traffic for TCP port: 443
2015-02-01 20:28:40,937 Excluding all traffic for TCP port: 22
```

## License

The MIT License (MIT)

Copyright (c) 2014 by David Olander

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

