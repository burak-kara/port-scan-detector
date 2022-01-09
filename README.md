Another version of the pyscanlogger by John-Lin for a course project.
Original repo can be found here: https://github.com/John-Lin/pyscanlogger/blob/master/pyscanlogger.py

Pyscanlogger
============

Pyscanlogger - Python Port scan detector

A pure Python program to detect network port scanning attacks. Currently, logs different TCP port scans. Can run in the background like a daemon and log attacks to a log file.

The latest code for this including some added features can be seen here http://code.google.com/p/pyscanlogd/

### Required Packages
----
Pyscanlogger is dependent on pypcap and dpkt packages.

- **pypcap** is available from https://pypi.python.org/pypi/pypcap
- **dpkt** is available from http://code.google.com/p/dpkt/ 


### Install
----

Install pypcap and dpkt from their project pages.

1. Download dpkt source code from http://code.google.com/p/dpkt/ 
2. extract file and move to dpkt folder
3. python setup.py build 
4. sudo python setup.py install 

Install pypcap via pip install

sudo pip install pypcap

### Usage
----

To run with default options just run the tool as root.

`$ sudo python pyscanlogger.py`

To log a file pass the "-f" option.

`$ sudo python pyscanlogger.py -f "./scanlog.log"`

To run daemon pass the "-d" option.

`$ sudo python pyscanlogger.py -d -f "./scanlog.log"`

Note: When running as daemon, if -f option is not provided, no output is printed to stdout.


### Referenced from
---

- http://code.activestate.com/recipes/576690-pyscanlogger-python-port-scan-detector/

