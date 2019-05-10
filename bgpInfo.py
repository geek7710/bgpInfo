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
import pprint


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

class RecursiveLookup(object):

    def is_tunnel(self, source_interface):
        if 'Tunnel' in source_interface:
            bgp_logger.info('Found a Tunnel Interface')
            nbma_end_ip = self.show_dmvpn_interface(source_interface,
                                                     neighbor_ip)
            bgp_logger.info('nbma Tunnel %s'%nbma_end_ip)
        else:
            bgp_logger.info('Found no Tunnel Interface')
            nbma_end_ip = None

        if nbma_end_ip:
            bgp_logger.info('Found a Tunnel Interface and '
                'nbma ip address')
            tunnel_dest_ip, source_interface = self.show_ip_cef(nbma_end_ip)
            bgp_logger.info('nexthop_ip %s , source_interface %s'%
                (nbma_end_ip, source_interface))
        return (nbma_end_ip, source_interface)

class QueryLogs(object):
    ''' This class will contain all logs related methods '''
    def __init__(self, ci_fqdn):
        self.ci_fqdn = ci_fqdn
        self.pp = pprint.PrettyPrinter(indent=2)

    def query_lcat(self, interface_name):
        bgp_logger.info('query_lcat() Method')
        ci_name_short = self.ci_fqdn.split('.')[0]
        ci_name_pattern = re.compile(r'\s+(%s)'%self.ci_fqdn, re.IGNORECASE)
        try:
            lcat_process = subprocess.Popen(
                    ['lcat','silo'], stdout=subprocess.PIPE)
            grep1_process = subprocess.Popen(
                    ['grep',ci_name_short], stdin=lcat_process.stdout,
                    stdout=subprocess.PIPE)
            grep2_process = subprocess.Popen(
                    ['grep',interface_name], stdin=grep1_process.stdout,
                    stdout=subprocess.PIPE)
            stdout = grep2_process.communicate()[0]
            stdout = stdout.split('\n')
            bgp_logger.info('Log Information: %s'% self.pp.pformat(stdout))
        except Exception as err:
            bgp_logger.info(err)
            raise SystemExit(
                "I am not able to query silo logs\n")

    def query_cisco_device_log(self):
        pass

class CiscoCommands(RecursiveLookup):
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
        cef_interface_pattern = re.compile(r'(?:\s+)(\S+)(?:\s+)(\S+)$')
        ip_pattern = re.compile(r'(\d+\.\d+\.\d+.\d+)')
        for line in output[1:]:
            if cef_interface_pattern.search(line):
                nexthop_ip = cef_interface_pattern.search(line).group(1)
                outbound_if = cef_interface_pattern.search(line).group(2)
                if ip_pattern.search(nexthop_ip):
                    return nexthop_ip, outbound_if
                else:
                    return None, outbound_if

    def show_dmvpn_interface(self, source_interface, neighbor_ip):
        ''' retrieve dmvpn information '''
        bgp_logger.info('show_dmvpn_interface() method')
        self.command = ('show dmvpn interface ' + source_interface + 
                        ' | i ' + neighbor_ip + " ")

        dmvpn_output_pattern = re.compile(r'(?:^\s+\d+\s)(\S+)(?:\s+\S+\s+)')
        output = self.run_cisco_commands()
        for line in output[1:]:
            if dmvpn_output_pattern.search(line):
                return dmvpn_output_pattern.search(line).group(1)

    def show_vrf_config(self, nbma_interface):
        ''' this method will verify if nbma address 
            is reachable through a vrf '''
        bgp_logger.info('show_vrf_config() method')
        self.command = ('sh run int ' + nbma_interface + " | i vrf")
        vrf_name_pattern = re.compile(r'(?:\s+vrf\s+forwarding\s+)(\S+)')
        output = self.run_cisco_commands()
        vrf_name = None
        for line in output:
            if vrf_name_pattern.search(line):
                vrf_name = vrf_name_pattern.search(line).group(1)
                bgp_logger.info('found a VRF: %s'% vrf_name)
                return vrf_name
        if not vrf_name:
            bgp_logger.info('did not find a VRF')
            return None

    def show_intf_desciption(self, nbma_interface):
        ''' This method will extract interface description
            if there's a circuit ID it can be used to open
            a carrier ticket '''
        bgp_logger.info('show_interface_desciption() method')
        self.command = 'show run int ' + nbma_interface + ' | i description'
        output = self.run_cisco_commands()
        description = None
        int_desc_pattern = re.compile(r'(?:description\s+)(.+)')
        for line in output[1:]:
            if int_desc_pattern.search(line):
                description = int_desc_pattern.search(line).group(1)
                return description
        if not description:
            return None

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
        for line in output:
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

    query_logging = QueryLogs(ci_fqdn)

    if bgp_as:
        nexthop_ip, source_interface = bgp.show_ip_cef(neighbor_ip)
        bgp_logger.info("nexthop ip: %s , interface %s"%
            (nexthop_ip,source_interface))

        # if cef points to a Tunnel then recursive lookup
        # to find nmba tunnel destination IP
        if 'Tunnel' in source_interface:
            tunnel_dest_ip, source_interface = (
                bgp.is_tunnel(source_interface))
        else:
            tunnel_dest_ip = None

        # look if there's a VRF associated with interface
        if nexthop_ip:
            vrf_name = bgp.show_vrf_config(source_interface)
        if tunnel_dest_ip:
            vrf_name = bgp.show_vrf_config(source_interface)

        # query the silo logs for interface flap
        if nexthop_ip:
            query_logging.query_lcat(source_interface)
        if tunnel_dest_ip:
            query_logging.query_lcat(source_interface)

        # if vrf associated with interface, use it to ping
        # gateway, other endpoint or end of tunnel nbma
        if vrf_name:
            if nexthop_ip:
                ping_vrf_results = bgp.ping_through_vrf(
                                    vrf_name, nexthop_ip)
            if tunnel_dest_ip:
                ping_vrf_results = bgp.ping_through_vrf(
                                    vrf_name, tunnel_dest_ip)
        
        # Retreive Interface Description
        if nexthop_ip:
            description = bgp.show_intf_desciption(source_interface)
            if description:
                bgp_logger.info('Interface description: %s'% description)
            else:
                bgp_logger.info('No interface description found!')
        if tunnel_dest_ip:
            description = bgp.show_intf_desciption(source_interface)
            if description:
                bgp_logger.info('Interface description: %s'% description)
            else:
                bgp_logger.info('No interface description found!'

        if not vrf_name:
            if nexthop_ip:
                ping_results = bgp.ping_through_to_end_ip(
                    nexthop_ip)
            if tunnel_dest_ip:
                ping_results = bgp.ping_through_to_end_ip(
                    tunnel_dest_ip)    
    else:
        raise SystemExit("This device does not run BGP")


if __name__ == '__main__':
    #  bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net
    # Initializing Dictionary to Store BGP information
    try:
        bgp_dict = lambda: defaultdict(bgp_dict)
        bgp_info_dict = bgp_dict()
        __slots__ = bgp_info_dict

        # Initialize logging module
        LoggerClass.logging()

        ci_fqdn, neighbor_ip = argument_parser()

        bgp_orchestrator(ci_fqdn, neighbor_ip)
    except KeyboardInterrupt:
        raise SystemExit("APPLICATION TERMINATED!")

