#!/usr/bin/python

from __future__ import print_function
from subprocess import *
from optparse import OptionParser
from collections import defaultdict
import re
import datetime
import sys
import os
import logging


class LoggerClass(object):
    """ 
        This class is created to instantiate logging functionality
        in this script. It is possible to create a logging filehandle
        that can store logging info in a file. This file is located
        in the same directory where the script is running by default
    """
    def __init__(self):
        today = datetime.date.today()
        mydate = str(today.year) + "-" + str(today.month) + "-" + str(today.day)

        #LOG_FILENAME = "bgpInfoScript_" + mydate + ".log"
        self.bgpLogger = logging.getLogger(__name__)
        self.bgpLogger.setLevel(logging.INFO)
        self.bgpLogger.disabled = False

        #self.fileLog = logging.FileHandler(LOG_FILENAME)
        #self.fileLog.setLevel(logging.INFO)

        self.streamLog = logging.StreamHandler()
        self.streamLog.setLevel(logging.INFO)

        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        #self.fileLog.setFormatter(formatter)
        self.streamLog.setFormatter(self.formatter)

        #self.bgpLogger.addHandler(fileLog)
        self.bgpLogger.addHandler(self.streamLog)


class VerifyUserInput(LoggerClass):
    """
    Verify User input: ciName against the /etc/host file.
    """
    def __init__(self, ciName=None):
        self.ciName = ciName

    def verifyEtcHost(self):
        self.bgpLogger.info('inside VerifyEtcHost method')
        ''' run cat /etc/hosts and get list of devices '''
        # declaring function scope variable
        if self.ciName == None:
            print("Enter router name")
            sys.exit()
        else:
            hostPattern = re.compile(r'\s+(%s)$'%self.ciName, re.IGNORECASE)
            try:
                proc = subprocess.Popen(
                                ['cat','/etc/hosts'], stdout=subprocess.PIPE)
                stdout = proc.communicate()[0]
                stdout = stdout.split('\n')
            except:
                raise SystemExit(
                    "I am not able to find your BGP ROUTER on this BMN\n")

        for line in stdout:
            if hostPattern.search(line):
                verified = True
                break
        if not verified:
            raise SystemExit("I cannot find %s as a managed device"
                         " in this BMN"%deviceName)


def main():
    ''' Run argument parser to verify what user wants to do '''
    parser = OptionParser(usage="\nOPTION: %prog -d <ciName>\n\n"
    "EXAMPLE: bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net\n\n"
    "ALSO TO PRINT HELP: %prog --help to print this information",
    version="%prog 1.0")
    parser.add_option("-d", "--device",
                    action="store", # optional because action defaults to "store"
                    dest="ciName",
                    help="ciName is a REQUIREMENT to run this script",)
    (options, args) = parser.parse_args()
    if options.ciName:
        print("You entered %s"%options.ciName)
    else:
        parser.error("You need to provide a ciName to run this Script\n\n")


if __name__ == '__main__':

    # Initializing Dictionary to Store BGP information
    bgpDict = lambda: defaultdict(bgpDict)
    bgpInfoDict = bgpDict()
    __slots__ = bgpInfoDict

    main()
