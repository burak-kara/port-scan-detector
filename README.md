Another version of the pyscanlogger by John-Lin for a course project.
Original repo can be found here: https://github.com/John-Lin/pyscanlogger/blob/master/pyscanlogger.py

### Usage
----

To run with default options just run the tool as root.

`$ sudo python pyscanlogger3.py`

The canlog file can be found in the project root.

Pyscanlogger
============

Pyscanlogger - Python Port scan detector

A pure Python program to detect network port scanning attacks. Currently, logs different TCP port scans. Can run in the background like a daemon and log attacks to a log file.

The latest code for this including some added features can be seen here http://code.google.com/p/pyscanlogd/

## Required Packages
----
Pyscanlogger is dependent on pypcap and dpkt packages.

- **pypcap** is available from https://pypi.python.org/pypi/pypcap
- **dpkt** is available from http://code.google.com/p/dpkt/ 


### Install
----
sudo pip install pypcap
sudo pip install dpkt

## Referenced from
---
- https://github.com/John-Lin/pyscanlogger/blob/master/pyscanlogger.py
- http://code.activestate.com/recipes/576690-pyscanlogger-python-port-scan-detector/

