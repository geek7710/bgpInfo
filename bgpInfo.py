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
    Verify User input: ci_name against the /etc/host file.
    return ci_name + domain name:
    wp-nwk-atm-xr.gpi.remote.binc.net
    """
    def __init__(self, ci_name=None):
        self.ci_name = ci_name
        self.verified = None
        
    def verify_etc_hosts(self):
        bgp_logger.info('inside verify_etc_hosts() method')
        ''' run cat /etc/hosts and get list of devices '''
        # declaring function scope variable
        if self.ci_name == None:
            print("You didn't include ci_name")
            return False
        else:
            host_pattern = re.compile(r'\s+(%s)'%self.ci_name, re.IGNORECASE)
            try:
                proc = subprocess.Popen(
                        ['cat','/etc/hosts'], stdout=subprocess.PIPE)
                stdout = proc.communicate()[0]
                stdout = stdout.split('\n')
            except Exception as err:
                bgp_logger.info(err)
                raise SystemExit(
                    "I am not able to find your BGP ROUTER on this BMN\n")
        # Initialize the verified variable if ci_name is not found in
        # /etc/hosts script will exit
        for line in stdout:
            if host_pattern.search(line):
                verified = True
                if len(line.split()) == 3:
                    bgp_logger.info(line.split()[1])
                    ci_fqdn = line.split()[1]
                    return ci_fqdn
                else:
                    bgp_logger.info("This looks different\n" + line)
                    return False
                bgp_logger.info(host_pattern.search(line).group(0).strip())
        # verified will be None if no FQDN was found
        if self.verified == None:
            print("I cannot find %s as a managed device"
                         " in this BMN"%self.ci_name)
            return False


class LoggerClass(object):
    """ This class is created to initialize logging functionality
    in this script. It is possible to create a logging filehandle
    that can store logging info in a file. This file is located
    in the same directory where the script is running by default.
    To have the script generate script logging remove the hash in the 
    commented out lines below. """
    @staticmethod
    def logging():
        today = datetime.date.today()
        mydate = (str(today.year) + "-" + str(today.month) + 
                 "-" + str(today.day))

        # log_filename = "bgpInfoScript_" + mydate + ".log"
        global bgp_logger
        bgp_logger = logging.getLogger(__name__)
        bgp_logger.setLevel(logging.INFO)
        bgp_logger.disabled = False

        # self.file_log = logging.FileHandler(log_filename)
        # self.file_log.setLevel(logging.INFO)

        streamLog = logging.StreamHandler()
        streamLog.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s '
                                      '- %(message)s')

        # self.file_log.setFormatter(formatter)
        streamLog.setFormatter(formatter)

        # self.bgp_logger.addHandler(file_log)
        bgp_logger.addHandler(streamLog)


class CiscoCommands(object):
    ''' This class will run any bgp related commands '''

    def __init__(self, ci_name):
        self.ci_name = ci_name
        self.command = None

    def verify_ip_protocols(self):
        ''' This method will verify BGP is configured '''
        bgp_logger.info('verify_ip_protocols() method')
        self.command = 'show ip protocol | s bgp'
        bgp_as_pattern = re.compile(r'(bgp\s+\d+)')
        output = self.run_cisco_commands()
        for line in output:
            if bgp_as_pattern.search(line):
                print("This device runs BGP: %s"%
                      bgp_as_pattern.search(line).group(1))
                return True
            
    def clean_clogin_output(self,clogin_output):
        bgp_logger.info('clean_clogin_output() method')
        ''' remove prompt output from clogin output '''
        for index, line in enumerate(clogin_output):
            if self.command in line:
                start = index
            if 'exit' in line:
                end = index
        return clogin_output[start:end]

    def run_cisco_commands(self):
        bgp_logger.info('run_cisco_commands() method')
        ''' Run clogin to retrieve command information 
        from device '''
        try:
            clogin_process = subprocess.Popen(['sudo','-u','binc',
                                          '/opt/sbin/clogin',
                                          '-c',self.command,self.ci_name],
                                          stdout=subprocess.PIPE)
            clogin_output = clogin_process.communicate()[0]
            clogin_output = clogin_output.split('\r\n')
            return self.clean_clogin_output(clogin_output)
        except Exception as err:
            raise SystemExit('clogin process failed for device: %s\n'
                             'ERROR: %s'%(self.ci_name, err))

    def show_ip_cef(self, ip_address):
        bgp_logger.info('show_ip_cef() method')
        self.command = 'show ip cef ' + ip_address
        output = self.run_cisco_commands()
        cef_interface_pattern = re.compile(r'(?:\S+\s+)(\S+)$')
        for line in output[1:]:
            if cef_interface_pattern.search(line):
                return cef_interface_pattern.search(line).group(1)

    def show_dmvpn_interface(self, source_interface, neighbor_ip):
        ''' retrieve dmvpn information '''
        bgp_logger.info('show_dmvpn_interface() method')
        self.command = ('show dmvpn interface ' + source_interface + 
                        ' | i ' + neighbor_ip)

        dmvpn_output_pattern = re.compile(r'(?:^\s+\d+\s)(\S+)(?:\s+\S+\s+)')
        output = self.run_cisco_commands()
        for line in output[1:]:
            if dmvpn_output_pattern.search(line):
                return dmvpn_output_pattern.search(line).group(1)

    def show_vrf_config(self, nbma_interface):
        ''' this method will verify if nbma address 
            is reachable through a vrf '''
        bgp_logger.info('show_vrf_config() method')
        self.command = ('show ip vrf')
        interface_number_pattern = re.compile(r'(?:\w+)(\d+\S+)')
        vrf_name_pattern = re.compile(r'(?:^\s+)(\S+)(\s+)')
        interface_number = str(
            interface_number_pattern.match(nbma_interface).group(1))
        output = self.run_cisco_commands()
        for line in output[1:]:
            if interface_number in line:
                return vrf_name_pattern.search(line).group(1)

    def ping_through_vrf(self, vrf_name, nbma_end_ip):
        ''' this method will ping nbma end point ip address 
            through vrf to test carrier connectivity '''
        bgp_logger.info('ping_through_vrf() method')
        self.command = "ping vrf " + vrf_name + " " + nbma_end_ip
        output = self.run_cisco_commands()
        for line in output[1:]:
            print(line)

    def ping_through_to_end_ip(self, nbma_end_ip):
        ''' this method will ping nbma end point ip address to test
            ip connectivity '''
        bgp_logger.info('ping_through_to_end_ip() method')
        self.command = "ping " + nbma_end_ip
        output = self.run_cisco_commands()
        for line in output[1:]:
            print(line)


def argument_parser():
    ''' Run argument parser to verify what user wants to do '''
    parser = OptionParser(usage="\nOPTION: %prog -d <ci_name> "
                                "-n <ipAddress>\n\n"
    "EXAMPLE: bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net -n 8.9.10.11\n\n"
    "ALSO TO PRINT HELP: %prog --help to print this information",
    version="%prog 1.0")
    parser.add_option("-d", "--device",
                    # optional because action defaults to "store"
                    action="store", 
                    dest="ci_name",
                    help="ci_name is a REQUIREMENT to run this script",)
    parser.add_option("-n", "--neighbor",
                    action="store",
                    dest="neighbor_ip",
                    help="BGP Neighbor IP address is a REQUIREMENT",)
    (options, args) = parser.parse_args()
    if options.ci_name and options.neighbor_ip:
        user_input = VerifyUserInput(options.ci_name)
        ci_name_verified = user_input.verify_etc_hosts()
        if not ci_name_verified:
            raise SystemExit('Terminating Script!')
        else:
            return (ci_name_verified, options.neighbor_ip)
    else:
        parser.error("You need to provide ci_name and BGP Neighbor"
                     " IP to run this Script\n\n")


def bgp_orchestrator(ci_fqdn, neighbor_ip):
    bgp_logger.info('bgp_orchestrator() method')
    bgp = CiscoCommands(ci_fqdn)
    bgp_as = bgp.verify_ip_protocols()
    if bgp_as:
        source_interface = bgp.show_ip_cef(neighbor_ip)
        print(source_interface)
        if 'Tunnel' in source_interface:
            nbma_end_ip = bgp.show_dmvpn_interface(source_interface,
                                                     neighbor_ip)
            print(nbma_end_ip)
        if nbma_end_ip:
            nbma_interface = bgp.show_ip_cef(nbma_end_ip)
            print(nbma_interface)
        if nbma_interface:
            vrf_name = bgp.show_vrf_config(nbma_interface)
        if vrf_name:
            print("Testing Connectivity to: " + nbma_end_ip + "through: " + 
                vrf_name + "\n")
            ping_vrf_results = bgp.ping_through_vrf(vrf_name, nbma_end_ip)
        if not vrf_name:
            print("Testing Connectivity to: " + nbma_end_ip + "\n")
            ping_results = bgp.ping_through_to_end_ip(nbma_end_ip)
    else:
        raise SystemExit("This device does not run BGP")


if __name__ == '__main__':
    #  bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net
    # Initializing Dictionary to Store BGP information
    bgp_dict = lambda: defaultdict(bgp_dict)
    bgp_info_dict = bgp_dict()
    __slots__ = bgp_info_dict

    # Initialize logging module
    LoggerClass.logging()

    ci_fqdn, neighbor_ip = argument_parser()

    bgp_orchestrator(ci_fqdn, neighbor_ip)
