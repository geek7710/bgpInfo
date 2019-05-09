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


class VerifyUserInput(object):
    """
    Verify User input: ciName against the /etc/host file.
    return ciname + domain name:
    wp-nwk-atm-xr.gpi.remote.binc.net
    """
    def __init__(self, ciName=None):
        self.ciName = ciName
        self.verified = None
        
    def verifyEtcHost(self):
        bgpLogger.info('inside VerifyEtcHost() method')
        ''' run cat /etc/hosts and get list of devices '''
        # declaring function scope variable
        if self.ciName == None:
            print("You didn't include ciName")
            return False
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
        for line in stdout:
            if hostPattern.search(line):
                verified = True
                if len(line.split()) == 3:
                    bgpLogger.info(line.split()[1])
                    ciFQDN = line.split()[1]
                    return ciFQDN
                else:
                    bgpLogger.info("This looks different\n" + line)
                    return False
                bgpLogger.info(hostPattern.search(line).group(0).strip())
        # verified will be None if no FQDN was found
        if self.verified == None:
            print("I cannot find %s as a managed device"
                         " in this BMN"%self.ciName)
            return False


class LoggerClass(object):
    """ This class is created to initialize logging functionality
    in this script. It is possible to create a logging filehandle
    that can store logging info in a file. This file is located
    in the same directory where the script is running by default.
    To have the script generate script logging remove the hash in the 
    commented out lines below."""
    @staticmethod
    def logging():
        today = datetime.date.today()
        mydate = (str(today.year) + "-" + str(today.month) + 
                 "-" + str(today.day))

        # LOG_FILENAME = "bgpInfoScript_" + mydate + ".log"
        global bgpLogger
        bgpLogger = logging.getLogger(__name__)
        bgpLogger.setLevel(logging.INFO)
        bgpLogger.disabled = False

        # self.fileLog = logging.FileHandler(LOG_FILENAME)
        # self.fileLog.setLevel(logging.INFO)

        streamLog = logging.StreamHandler()
        streamLog.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s '
                                      '- %(message)s')

        # self.fileLog.setFormatter(formatter)
        streamLog.setFormatter(formatter)

        # self.bgpLogger.addHandler(fileLog)
        bgpLogger.addHandler(streamLog)


class BgpCommands(object):
    ''' This class will run any bgp related commands '''

    def __init__(self, ciName):
        self.ciName = ciName
        self.command = None

    def verifyIPprotocols(self):
        ''' This method will verify BGP is configured '''
        bgpLogger.info('verifyIPprotocols() method')
        self.command = 'show ip protocol | s bgp'
        bgpPattern = re.compile(r'(bgp\s+\d+)')
        output = self.runCiscoCommand()
        for line in output:
            if bgpPattern.search(line):
                print("This device runs BGP: %s"%
                      bgpPattern.search(line).group(1))
                return True
            
    def cleanCloginOutput(self,cloginOutput):
        bgpLogger.info('cleanCloginOutput() method')
        ''' remove prompt output from clogin output '''
        for index, line in enumerate(cloginOutput):
            if self.command in line:
                start = index
            if 'exit' in line:
                end = index
        return cloginOutput[start:end]

    def runCiscoCommand(self):
        bgpLogger.info('runCiscoCommand() method')
        ''' Run clogin to retrieve command information 
        from device '''
        try:
            cloginProcess = subprocess.Popen(['sudo','-u','binc',
                                          '/opt/sbin/clogin',
                                          '-c',self.command,self.ciName],
                                          stdout=subprocess.PIPE)
            cloginOutput = cloginProcess.communicate()[0]
            cloginOutput = cloginOutput.split('\r\n')
            return self.cleanCloginOutput(cloginOutput)
        except Exception as err:
            raise SystemExit('clogin process failed for device: %s\n'
                             'ERROR: %s'%(self.ciName, err))


def argumentParser():
    ''' Run argument parser to verify what user wants to do '''
    parser = OptionParser(usage="\nOPTION: %prog -d <ciName> "
                                "-n <ipAddress>\n\n"
    "EXAMPLE: bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net -n 8.9.10.11\n\n"
    "ALSO TO PRINT HELP: %prog --help to print this information",
    version="%prog 1.0")
    parser.add_option("-d", "--device",
                    # optional because action defaults to "store"
                    action="store", 
                    dest="ciName",
                    help="ciName is a REQUIREMENT to run this script",)
    parser.add_option("-n", "--neighbor",
                    action="store",
                    dest="neighbor_ip",
                    help="BGP Neighbor IP address is a REQUIREMENT",)
    (options, args) = parser.parse_args()
    if options.ciName and options.neighbor_ip:
        usrInput = VerifyUserInput(options.ciName)
        ciNameVerified = usrInput.verifyEtcHost()
        if not ciNameVerified:
            raise SystemExit('Terminating Script!')
        else:
            return ciNameVerified
    else:
        parser.error("You need to provide ciName and BGP Neighbor"
                     " IP to run this Script\n\n")


def bgpOrchestrator(ciFQDN):
    bgpLogger.info('bgpOrchestrator() method')
    BGP = BgpCommands(ciFQDN)
    if BGP.verifyIPprotocols():
        print("This router runs: %s"%BGP)
        


if __name__ == '__main__':
    #  bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net
    # Initializing Dictionary to Store BGP information
    bgpDict = lambda: defaultdict(bgpDict)
    bgpInfoDict = bgpDict()
    __slots__ = bgpInfoDict

    # Initialize logging module
    LoggerClass.logging()

    ciFQDN = argumentParser()

    bgpOrchestrator(ciFQDN)
