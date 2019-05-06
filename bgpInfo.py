#!/usr/bin/python

from __future__ import print_function
from optparse import OptionParser
from collections import defaultdict
import subprocess
import re
import datetime
import sys
import os
import logging


class LoggerClass(object):
    """ 
        This class is created to initialize logging functionality
        in this script. It is possible to create a logging filehandle
        that can store logging info in a file. This file is located
        in the same directory where the script is running by default.
        To have the script generate script logging remove the hash in the 
        commented out lines below. 
    """
    @staticmethod
    def logging():
        today = datetime.date.today()
        mydate = str(today.year) + "-" + str(today.month) + "-" + str(today.day)

        #LOG_FILENAME = "bgpInfoScript_" + mydate + ".log"
        global bgpLogger
        bgpLogger = logging.getLogger(__name__)
        bgpLogger.setLevel(logging.INFO)
        bgpLogger.disabled = False

        #self.fileLog = logging.FileHandler(LOG_FILENAME)
        #self.fileLog.setLevel(logging.INFO)

        streamLog = logging.StreamHandler()
        streamLog.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        #self.fileLog.setFormatter(formatter)
        streamLog.setFormatter(formatter)

        #self.bgpLogger.addHandler(fileLog)
        bgpLogger.addHandler(streamLog)


class VerifyUserInput(object):
    """
    Verify User input: ciName against the /etc/host file.
    return ciname + domain name:
    wp-nwk-atm-xr.gpi.remote.binc.net
    """
    def __init__(self, ciName=None):
        self.ciName = ciName

    def verifyEtcHost(self):
        bgpLogger.info('inside VerifyEtcHost method')
        ''' run cat /etc/hosts and get list of devices '''
        # declaring function scope variable
        if self.ciName == None:
            print("Enter router name")
            sys.exit()
        else:
            hostPattern = re.compile(r'\s+(%s)'%self.ciName, re.IGNORECASE)
            try:
                proc = subprocess.Popen(
                        ['cat','/etc/hosts'], stdout=subprocess.PIPE)
                stdout = proc.communicate()[0]
                stdout = stdout.split('\n')
            except Exception as err:
                bgpLogger.info(err)
                raise SystemExit(
                    "I am not able to find your BGP ROUTER on this BMN\n")
        # Initialize the verified variable if ciName is not found in
        # /etc/hosts script will exit
        verified = None
        for line in stdout:
            if hostPattern.search(line):
                verified = True
                if len(line.split()) == 3:
                    bgpLogger.info(line.split()[1])
                    ciFQDN = line.split()[1]
                else:
                    bgpLogger.info("This looks different\n" + line)

                bgpLogger.info(hostPattern.search(line).group(0).strip())
                break
        if verified == None:
            raise SystemExit("I cannot find %s as a managed device"
                         " in this BMN"%self.ciName)


def argumentParser():
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
        usrInput = VerifyUserInput(options.ciName)
        usrInput.verifyEtcHost()
    else:
        parser.error("You need to provide a ciName to run this Script\n\n")


if __name__ == '__main__':
    #  bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net
    # Initializing Dictionary to Store BGP information
    bgpDict = lambda: defaultdict(bgpDict)
    bgpInfoDict = bgpDict()
    __slots__ = bgpInfoDict

    #Initializing logger module
    LoggerClass.logging()

    argumentParser()
