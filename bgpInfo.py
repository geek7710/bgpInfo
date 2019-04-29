#!/usr/bin/python
import re
from subprocess import *
import time
import sys
import shlex
import os
import glob
import logging
import getpass
import inspect
from multiprocessing import Process


class LoggerClass(object):

    @staticmethod
    def logger():
        # setup logging module at class initialization
        self.bgpLogger = logging.getLogger(__name__)
        self.bgpLogger.setLevel(logging.INFO)
        self.bgpLogger.disabled = True
        # creating logging handlers
        cliHandler = logging.StreamHandler()
        cliHandler.setLevel(logging.INFO)
        # Create log string format and add it to Handlers
        cliFormat = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        cliHandler.setFormatter(cliFormat)

        # Adding handlers to the logger
        self.bgpLogger.addHandler(cliHandler)


class GetBGPInformation(object):

    def __init__(self):
        # Instantiate variables to be used throughout this class
        self.peerIP = ''
        self.hostname = ''
        self.bgpEvent = ''


    def inputFromUser(self):
        self.bgpEvent = raw_input("Enter Problem Short Description: ")
        if not self.bgpEvent:
            print "I cannot run without you entering the INCident short description\n"
            raise SystemExit


    def retreiveEventInformation(self):
        self.bgpLogger.info(inspect.stack()[0][3])
        bgpPeerIPPattern = re.compile(r'(?:.*neighbor\s+\*?)'
                                        '([0-9.]+)(?# this section will match IP address)'
                                        '(?:\s+Log message)'
                                        )
        bgpHostnamePattern = re.compile(r'(?:\s+)'
                                        '([0-9a-zA-Z-]+)(?#This group#2 will match hostname without domain)'
                                        '(?:\.\w+\.remote.*\.(binc.net|cdw.com))'
                                        )
        self.peerIP = (bgpPeerIPPattern.search(self.bgpEvent)).group(1)
        self.hostname = (bgpHostnamePattern.search(self.bgpEvent)).group(1)


        if self.peerIP:
            self.bgpLogger.info(self.peerIP)
            self.bgpLogger.info(self.hostname)
            self.bgpSummary.update({'PeerIP':self.peerIP})
            self.bgpSummary.update({'ciName':self.hostname})
            return self.peerIP, self.hostname
        else:
            print "I couldn't find relevant information BGP peer IP and CI name\n"
            self.bgpSummary.update({'PeerIP':None})
            self.bgpSummary.update({'ciName':None})
            raise SystemExit


    def runShellCommand(self, command):
        self.bgpLogger.info(inspect.stack()[0][3])
        # run shell commands module, you can pass any BMN shell command
        # it will run it and return output
        command = shlex.split(command)
        proc = Popen(command, stdout=PIPE)
        return proc.stdout.read()


    def getBGPSummary(self, command, peerIP, CI):
        self.bgpLogger.info(inspect.stack()[0][3])
        # This method retreive BGP summary information 
        # just for the BGP peer IP reported in ticket
        proc = Popen(['getlivedata', CI, 'clogin', command], stdout=PIPE)
        output = proc.stdout.readlines()
        for line in output:
            match = re.search(peerIP, line)
            if match:
                self.bgpLogger.info(line)
                self.bgpSummary.update({'bgpNeighborSummary':line})
                return line
            else:
                self.bgpSummary.update({'bgpNeighborSummary':None})


    def getBGPNeighborInfo(self, command, CI):
        self.bgpLogger.info(inspect.stack()[0][3])
        # This method will get local BGP Peer IP to query 
        # peer router BGP summary if peer is managed by CDW
        proc = Popen(['getlivedata', CI, 'clogin', command], stdout=PIPE)
        output = proc.stdout.readlines()
        for line in output:
            match = re.search(r'(?:Local host:\s+)(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                localBgpIP = match.group(1)
                self.bgpLogger.info(localBgpIP)
                self.bgpSummary.update({'bgpSourcePeerIP':localBgpIP})
                return localBgpIP


    def findManagedPeerIp(self, findStringOutput):
        # the following patter will match CI name only if followed by 'ip address'
        # keyword on next line
        self.bgpLogger.info(inspect.stack()[0][3])
        peerCIpattern = re.compile(r'(?:Device:\s+)(.*)(?:\n\s+?ip address\s+?)',re.MULTILINE)
        matchCI = peerCIpattern.search(findStringOutput)
        # Set a condition to make sure correct CI name was found
        if matchCI:
            ciName = matchCI.group(1)
            ciName = self.trimCI(ciName)
            self.bgpSummary.update({'remotePeerCIName':ciName})
            self.bgpLogger.info(ciName)
        else:
            ciName = None
            self.bgpSummary.update({'remotePeerCIName':None})
        return ciName


    def trimCI(self, ciName):
        self.bgpLogger.info(inspect.stack()[0][3])
        # the following RegEx pattern will match CI+domain_name and extract only CI name
        ciNamePattern = re.compile(r'(.*)(:?\..*\.remote.*\.(binc.net|cdw.com))')
        matchCI = ciNamePattern.search(ciName)
        if matchCI:
            CI = matchCI.group(1)
        else:
            CI = None
        return CI


    def getBZ2(self):
        self.bgpLogger.info(inspect.stack()[0][3])
        # go into logdir section on the customer BMN 
        # and pull last bz2 file generated to be parse
        year = (self.runShellCommand('date "+%Y"')).strip()
        month = (self.runShellCommand('date "+%m"')).strip()
        day = (self.runShellCommand('date "+%d"')).strip()
        os.chdir('/home/archive/alllog/' + year + '/' + month +'/')

        # the string will look for today's bz2 file that ends in 10-05-2018.bz2 format
        dateFormat = month + "-" + day + "-" + year + ".bz2"

        #following command should pull the last syslog file generated
        #pi-s-bmn03-all.log-10-02-2018.bz2
        bz2Files = glob.glob("*.bz2")
        for file in bz2Files:
            if dateFormat in file:
                self.bgpLogger.info(file)
                self.bgpSummary.update({'bz2File':file})
                return file
            else:
                self.bgpSummary.update({'bz2File':None})


    def findBGPLogInfo(self, ciName, peerIP, bz2File):
        self.bgpLogger.info(inspect.stack()[0][3])
        # each of p2 .. p5 are grep commands after pip in linux CLI
        # this is a workaround to shell=True flag under subprocess command
        p1 = Popen(['bzcat',bz2File], stdout=PIPE)
        p2 = Popen(['grep','BGP'], stdin=p1.stdout, stdout=PIPE)
        p3 = Popen(['grep',ciName], stdin=p2.stdout, stdout=PIPE)
        p4 = Popen(['tail', '-n30'],stdin=p3.stdout, stdout=PIPE)

        # log match entries, last 20 from syslog, will be saved into the
        # following variable

        logOutput = p4.stdout.readlines()

        # need to clean that output and just leave anything from
        # date timestamp and on
        logPattern = re.compile(r'(?:.*\[\]:\s+)(.*)')
        logOutputClean = []

        for line in logOutput:
            matchLog = logPattern.search(line)
            if matchLog:
                logOutputClean.append(matchLog.group(1))
                self.bgpLogger.info(matchLog.group(1))

        if logOutputClean:
            self.bgpSummary.update({'sysLogInfo':logOutputClean})
            return logOutputClean
        else:
            self.bgpSummary.update({'sysLogInfo':None})
            return None

    def runGetLiveData(self, command, ciName):
        # This is a method that will run getlivedata and return output
        self.bgpLogger.info(inspect.stack()[0][3])
        proc = Popen(['getlivedata', ciName, 'clogin', command], stdout=PIPE)
        output = proc.stdout.readlines()

        return output


    def interfaceRecursiveFind(self, ciName, peerIP):
        self.bgpLogger.info(inspect.stack()[0][3])
        # find recursively Inteface sourcing local BGP peer
        # if Interface is other than loopback, it will help track any circuit flap

        # Initializing Variable
        command = "show ip cef " + peerIP
        output = self.runGetLiveData(command, ciName)
        # the following loop will look for Tunnel interface
        tunnelIntf = None
        for line in output:
            matchTunnel = re.search(r'(Tunn.*\d)$', line)
            if matchTunnel:
                self.bgpLogger.info(matchTunnel.group(1))
                tunnelIntf = matchTunnel.group(1)
        # if tunnelInterface then look for the tunnel source interface
        # to try to find the MPLS/Circuit interface
        if tunnelIntf:
            command = "sh run int " + tunnelIntf + " | i source" 
            output = self.runGetLiveData(command, ciName)
        # the following loop will run if no tunnel interface is found
        # and extract the physical interface from the router
        for line in output:
            match = re.search(r'(Giga.*\d|Cell.*\d|Loop.*\d|Serial.*\d)$', line)
            if match:
                self.bgpLogger.info(match.group(1))
                physicalInterface = match.group(1)
                self.bgpSummary.update({'interfaceID':physicalInterface})
                return physicalInterface      
        


    def getDescription(self, ciName, interface):
        # get interface description from interface of interest
        self.bgpLogger.info(inspect.stack()[0][3])
        command = "show run interface " + interface + " | i desc"
        output = self.runGetLiveData(command, ciName)
        for line in output:
            descriptionMatch = re.search(r'(description.*)$', line)
            if descriptionMatch:
                self.bgpLogger.info(descriptionMatch.group(1))
                interfaceDescription = descriptionMatch.group(1)
                self.bgpSummary.update({'interfaceDesc':interfaceDescription})
                return interfaceDescription
        if not descriptionMatch:
            self.bgpLogger.info("Interface Description is not configured")
            self.bgpSummary.update({'interfaceDesc':None})
            return "Interface Description is not configured"

    def lookForInterfaceFlap(self, ciName, interface):
        # this method will look for interface flaps on the BGP peer devices
        self.bgpLogger.info(inspect.stack()[0][3])
        self.bgpLogger.error("An error here")
        baseInterfacePattern = re.search(r'(.*)(?:\.|\:\d+)', interface)
        if baseInterfacePattern:
            baseInterfaceName = baseInterfacePattern.group(1)
            self.bgpLogger.info("I am looking in the device logs for: " + baseInterfaceName)
        else:
            baseInterfaceName = interface

        command = "show log | i changed state"
        output = self.runGetLiveData(command, ciName)
        interfaceFlapLog = []
        if output:
            for line in output:
                if baseInterfaceName in line and "show log" not in line:
                    interfaceFlapLog.append(line)
            self.bgpSummary.update({'interfaceFlap':interfaceFlapLog})
        else:
            self.bgpSummary.update({'interfaceFlap':None})
            print "Did not find any interface flap on the " + ciName + " logs"


def main():

    myBGP = GetBGPInformation()
    myBGP.inputFromUser()
    remoteBGP_PeerIP, ticketCI = myBGP.retreiveEventInformation()

    if not remoteBGP_PeerIP:
        print "I cannot find a BGP peering IP in the short description you entered"
        raise SystemExit
    else:
        os.system('clear')
        print "The INC short description\nPeer IP: %s\nThe CI Name is: %s\n\n"%(remoteBGP_PeerIP, ticketCI)
    
    bz2File = myBGP.getBZ2()
    if bz2File:
        print "Latest syslog file indenfied: %s\n\nI am looking for logging information...\n\n"%bz2File
    else:
        print "I was not able to read syslog\n\n"

    syslogProcess = Process(target=myBGP.findBGPLogInfo, args=(ticketCI, remoteBGP_PeerIP, bz2File))
    syslogProcess.daemon = True
    #logResults = myBGP.findBGPLogInfo(ticketCI, remoteBGP_PeerIP, bz2File)
    syslogProcess.start()

#    if logResults:
#        print "\nI have some logging information for you:\n"
#        print "===================== SYSLOG ======================\n"
#        for line in logResults:
#            print line
#        print "================= END OF SYSLOG ===================\n"
#    else:
#        print "I did not find any BGP entries related to this Event\n"


    print "I am verifying if Peer IP is a CDW managed device\n"
    # Query findstring to find if remote peer IP is managed by CDW
    findStringResults = myBGP.runShellCommand('findstring -d ' + remoteBGP_PeerIP)
    
    bgpNeighborCI = myBGP.findManagedPeerIp(findStringResults)
    if bgpNeighborCI:
        print "The peer ip belongs to:  %s\n"%bgpNeighborCI
    else:
        print "I was not able determine if peer IP is managed by CDW\n"

    print "Use RSA to login to CI and retreive BGP Neighbor information from: %s\n"%ticketCI

    # Query BGP summary on CID included on ticket short description
    try:
        bgpSession = myBGP.getBGPSummary('show ip bgp summary', remoteBGP_PeerIP, ticketCI)
        if bgpSession:
            print "BGP Peering Session Information from: %s\n"%ticketCI
            print bgpSession
        else:
            print "I am not able to pull BGP Peering Session Uptime from %s\n"%ticketCI
    except:
        print "VERIFY CI %S IS A VALID DEVICE TO THIS CUSTOMER\n"%ticketCI
        raise SystemExit

    localBGPIP = myBGP.getBGPNeighborInfo("show ip bgp neighbor " + remoteBGP_PeerIP + " | inc host:", ticketCI)
    # Get localPeerIP to Query remote peer for BGP status
    # and get interface description if available
    print "I am looking for any Circuit flap information on: %s\n"%ticketCI
    interfaceID = myBGP.interfaceRecursiveFind(ticketCI,remoteBGP_PeerIP)
    if interfaceID:
        print "I found interface ID that sources BGP Peering session:\n"
        print "%s\n"%interfaceID
        print "I am going to retrieve Interface %s Description if available\n"%interfaceID


    interfaceDescription = myBGP.getDescription(ticketCI, interfaceID)
    if interfaceDescription:
        print "Interfaces description information:\n\n%s"%interfaceDescription
    else:
        print "I have found no interface Description\n"
    # Look for interface flap in the device LOG

    if interfaceID:
        print "\n\nI am going to look for any Interface Status Information on the %s logs\n"%ticketCI
        deviceLog = myBGP.lookForInterfaceFlap(ticketCI, interfaceID)
        if deviceLog:
            print "Log information\n"
            for line in deviceLog:
                print line
        else:
            print "No information found on the device log about %s\n\n"%interfaceID

    if bgpNeighborCI:
        # Get remotePeer interfaces description
        print "\n\nNeighbor CI name: %s\n"%bgpNeighborCI
        peerInterfaceID = myBGP.interfaceRecursiveFind(bgpNeighborCI, localBGPIP)
        if peerInterfaceID:
            print "I found Interface: %s on remote CI"%peerInterfaceID
        interfaceDescription = myBGP.getDescription(bgpNeighborCI, peerInterfaceID)
        if interfaceDescription:
            print "\nI found the following interfaces description: \n%s"%interfaceDescription
        deviceLog = myBGP.lookForInterfaceFlap(bgpNeighborCI, peerInterfaceID)
        if deviceLog:
            print "Log information from Peer CI:\n"
            for line in deviceLog:
                print line
        else:
            print "No information found on the device log about %s"%interfaceID

    if syslogProcess.is_alive():
        syslogProcess.terminate()
        print "I was not able to retreive syslog information\n"
    else:
        print "syslog information was retrieved\n"


    print myBGP.bgpSummary

    print "MAKE SURE TO OPEN A TICKET WITH THE CARRIER"
    print "IF ANY INTERFACE FLAP WAS FOUND"