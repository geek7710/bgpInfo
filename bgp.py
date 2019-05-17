#!/usr/bin/python
from __future__ import print_function
from optparse import OptionParser
from collections import defaultdict
import subprocess
import re
# import datetime
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
        self.stdout = None
        self.ci_list = []
        self.ci_count = []

    def verify_etc_hosts(self):
        bgp_logger.info('verify_etc_hosts() method')
        ''' run cat /etc/hosts and get list of devices '''
        # declaring function scope variable
        if self.ci_name is None:
            print("You didn't include ci_name")
            return False
        else:
            try:
                proc = subprocess.Popen(
                        ['cat', '/etc/hosts'], stdout=subprocess.PIPE)
                self.stdout = proc.communicate()[0]
                self.stdout = self.stdout.split('\n')
            except Exception as err:
                bgp_logger.info(err)
                raise SystemExit(
                    "I am not able to find your BGP ROUTER on this BMN\n")
        # Initialize the verified variable if ci_name is not found in
        # /etc/hosts script will exit
        self.stdout = self.filter_findstring_output()
        self.stdout = self.verify_multiple_entries()

        # verified will be None if no FQDN was found
        if self.verified is None:
            print("I cannot find %s as a managed device"
                  " in this BMN" % self.ci_name)
            return False
        else:
            # because self.stdout was turned into a list, it now needs to
            # return the single item stripped out of list
            bgp_logger.info('RETURN FROM ETC/HOST %s' % self.stdout)
            return self.stdout

    def verify_multiple_entries(self):
        '''
        If multiple devices with similiar name are found,
        prompt user which device is the script going to run on
        '''
        bgp_logger.info('verify_multiple_entries() method')
        for line in self.stdout:
            if self.ci_name in line:
                self.ci_count.append(line)
        # go to print_menu, if user selects wrong
        # choice re-print the menu
        if len(self.ci_count) > 1:
            while True:
                self.print_menu()
                # prompt user to select device run the script on
                try:
                    selection = int(raw_input("Choise# "))
                    selection = selection - 1
                    if selection in self.ci_list:
                        break
                    else:
                        print("\n")
                        print("You enter and INVALID option. "
                              "Please Try again:\n")
                except Exception as err:
                    print("\n")
                    print("INPUT ERROR: %s" % err)
                    print("You enter and INVALID option. "
                          "Please Try again:\n")

            bgp_logger.info("SELECTION: %s" % self.ci_count[selection])
            return self.ci_count[selection]
        else:
            if isinstance(self.ci_count, list):
                return self.ci_count[0]
            else:
                return self.ci_count

    def print_menu(self):
        '''
        print menu if multiple devices with similar name
        '''
        print("I found multiple entries with similar name,\n"
              "Choose which ci you want to run this script on,\n"
              "Select a CI by using the number on the left:\n")
        # store the list of indexes
        for index, ci in enumerate(self.ci_count):
            self.ci_list.append(index)
            print(" %d) %s\n" % (index + 1, ci))
        return self.ci_list

    def filter_findstring_output(self):
        '''
        filter out unneeded fields and return only log ci_name
        "wp-hauppauge-sw.gpi.remote.hms.cdw.com"
        '''
        filtered = []
        bgp_logger.info('filter_findstring_output() methods')
        host_pattern = re.compile(r'\s+(%s)' % self.ci_name, re.IGNORECASE)
        for line in self.stdout:
            if host_pattern.search(line):
                self.verified = True
                if len(line.split()) == 3:
                    bgp_logger.info(line.split()[1])
                    ci_fqdn = line.split()[1]
                    filtered.append(ci_fqdn)
        bgp_logger.info("FILTERED FINDSTRING: %s" % filtered)
        return filtered


class RunFindstring(object):
    '''
    Run findstring on neighbor IP to verify if it is managed by CDW
    '''
    def __init__(self, neighbor_ip = None):
        self.neighbor_ip = neighbor_ip
        bgp_logger.info('run_findstring() class')

    def find_managed(self):
        '''
        run findstring to verify if neighbor ip address
        is managed by CDW
        '''
        bgp_logger.info('find_managed() method')
        if self.neighbor_ip is None:
            print("Neighbor IP is not valid")
            return False
        else:
            self.neighbor_ip = "ip address " + self.neighbor_ip + " "
            try:
                proc = subprocess.Popen(
                                        ['findstring','-d',
                                        self.neighbor_ip],
                                        stdout=subprocess.PIPE)
                grep = subprocess.Popen(['grep',
                                         'Device:'],
                                        stdin=proc.stdout,
                                        stdout=subprocess.PIPE)
                awk = subprocess.Popen(['awk',
                                        '{print $2}'],
                                        stdin=grep.stdout,
                                        stdout=subprocess.PIPE)
                stdout = awk.communicate()[0]
            except Exception as err:
                bgp_logger.info(err)
                raise SystemExit(
                    "I am not able to run findstring on this BMN\n")
        # Initialize the verified variable if ci_name is not found in
        # /etc/hosts script will exit
        if stdout:
            return stdout
        else:
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
        # today = datetime.date.today()
        # mydate = (str(today.year) + "-" + str(today.month) +
        #          "-" + str(today.day))

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
            bgp_logger.info('NBMA IP: %s' % nbma_end_ip)
        else:
            bgp_logger.info('Found no Tunnel Interface')
            nbma_end_ip = None

        if nbma_end_ip:
            tunnel_dest_ip, source_interface = self.show_ip_cef(nbma_end_ip)
            bgp_logger.info('nexthop_ip %s , source_interface %s' %
                            (nbma_end_ip, source_interface))
        return (nbma_end_ip, source_interface)


class QueryLogs(object):
    ''' This class will contain all logs related methods '''
    def __init__(self, ci_fqdn):
        self.ci_fqdn = ci_fqdn

    def query_lcat_intf_flap(self, interface_name):
        bgp_logger.info('query_lcat_intf_flap() Method')
        ci_name_short = self.ci_fqdn.split('.')[0]
        bgp_logger.info('CI SHORT NAME: %s' % ci_name_short)
        try:
            lcat_process = subprocess.Popen(
                    ['lcat', 'silo'], stdout=subprocess.PIPE)
            grep1_ci = subprocess.Popen(
                    ['grep', ci_name_short], stdin=lcat_process.stdout,
                    stdout=subprocess.PIPE)
            grep2_interface = subprocess.Popen(
                    ['grep', interface_name], stdin=grep1_ci.stdout,
                    stdout=subprocess.PIPE)
            stdout = grep2_interface.communicate()[0]
            stdout = stdout.split('\n')
            # return false if no %LINEPROTO-5-UPDOWN entry is found 
            # in log line
            for line in stdout:
                if 'UPDOWN' in line:
                    if len(stdout) > 10:
                        return stdout[-10:]
                    else:
                        return stdout
            else:
                return False
        except Exception as err:
            bgp_logger.info(err)
            print("Subprocess failed to retreive BGP\n"
                  " log information for bouncing interfaces\n")
            return False

    def query_lcat_bgp(self, neighbor_ip):
        '''
        Look for BGP flaps
        '''
        bgp_logger.info('query_lcat_bgp() Method')
        ci_name_short = self.ci_fqdn.split('.')[0]
        bgp_logger.info('CI SHORT NAME: %s' % ci_name_short)
        try:
            lcat_process = subprocess.Popen(
                    ['lcat', 'silo'], stdout=subprocess.PIPE)
            grep1_ci = subprocess.Popen(
                    ['grep', ci_name_short], stdin=lcat_process.stdout,
                    stdout=subprocess.PIPE)
            grep2_bgp = subprocess.Popen(
                    ['grep', 'BGP'], stdin=grep1_ci.stdout,
                    stdout=subprocess.PIPE)
            grep3_neighbor = subprocess.Popen(
                    ['grep', neighbor_ip], stdin=grep2_bgp.stdout,
                    stdout=subprocess.PIPE)
            stdout = grep3_neighbor.communicate()[0]
            stdout = stdout.split('\n')
            for line in stdout:
                if "BGP" in line:
                    if len(stdout) > 10:
                        return stdout[-10:]
                    else:
                        return stdout
            else:
                return False
        except Exception as err:
            bgp_logger.info(err)
            print("Subprocess failed to retrieve BGP\n"
                  " log information for Neighbor: %s" % neighbor_ip)
            return False


class AnalyzePingResults(object):
    '''
    determine if ping fails, packet drops.  
    '''
    def __init__(self, ping_results = False):
        self.ping_results = ping_results

    def anylize_pings(self):
        # below regex pattern
        # (?:Success\s+rate\s+is\s)(\d+)(?:\s+percent\s+)(\((\d+)\/(\d)\))
        bgp_logger.info('anylize_pings() method')
        srate_pat = re.compile('''(?:Success\s+rate\s+is\s)
                  (\d+)(?:\s+percent\s+)(\((\d+)\/(\d)\))''', re.VERBOSE)

        if self.ping_results:
            for line in self.ping_results:
                print(line)
                if srate_pat.match(line):
                    success_rate = int(srate_pat.match(line).group(1))
                    pings_sent = srate_pat.match(line).group(4)
                    success_pings = srate_pat.match(line).group(3)
            if success_rate == 0:
                print("Open a CARRIER TICKET."
                      " Circuit is not forwarding Traffic")
            if success_rate < 100:
                print("There are some PACKET LOSS, "
                      "This could be a TELCO ISSUE\n")
            if success_rate == 100:
                print("Ping results show Circuit is OK")
        else:
            print("Ping Results Were Not Received")      


class CiscoCommands(RecursiveLookup):
    ''' This class will run any bgp related commands '''

    def __init__(self, ci_name):
        self.ci_name = ci_name
        self.command = None

    def verify_ip_protocols(self):
        ''' This method will verify BGP is configured '''
        bgp_logger.info('verify_ip_protocols() method')
        self.command = 'show ip protocol'
        bgp_as_pattern = re.compile(r'(bgp\s+\d+)')
        output = self.run_cisco_commands()
        for line in output:
            if bgp_as_pattern.search(line):
                print("This device runs BGP: %s" %
                      bgp_as_pattern.search(line).group(1))
                return True

    def clean_clogin_output(self, clogin_output):
        bgp_logger.info('clean_clogin_output() method')
        ''' remove prompt output from clogin output '''
        # default values
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
        bgp_logger.info('CI: %s' % self.ci_name)
        bgp_logger.info('command: %s' % self.command)
        try:
            clogin_process = subprocess.Popen(['sudo', '-u', 'binc',
                                               '/opt/sbin/clogin',
                                               '-c', self.command,
                                              self.ci_name],
                                              stdout=subprocess.PIPE)
            clogin_output = clogin_process.communicate()[0]
            clogin_output = clogin_output.split('\r\n')
            return self.clean_clogin_output(clogin_output)
            #return clogin_output
        except Exception as err:
            raise SystemExit('clogin process failed for device: %s\n'
                             'ERROR: %s' % (self.ci_name, err))

    def show_bgp_summary(self, ip_address):
        '''
        pull show bgp neighbor information
        '''
        bgp_logger.info('show_bgp_neighbor method()')
        self.command = "show ip bgp summary"
        output = self.run_cisco_commands()
        bgp_logger.info('BGP SUMMARY: \n %s' % output[1:])

        # return a slice of the output, omitting the command entered
        return output[1:]

    def show_ip_cef(self, ip_address):
        bgp_logger.info('show_ip_cef() method')
        self.command = 'show ip cef ' + ip_address
        output = self.run_cisco_commands()
        cef_interface_pattern = re.compile(r'(?:\s+)(\S+)(?:\s+)([TGESC]\S+)$')
        ip_pattern = re.compile(r'(\d+\.\d+\.\d+.\d+)')
 
        for line in output:
            if cef_interface_pattern.search(line):
                nexthop_ip = cef_interface_pattern.search(line).group(1)
                outbound_intf = cef_interface_pattern.search(line).group(2)

        if ip_pattern.search(nexthop_ip):
            return nexthop_ip, outbound_intf
        else:
            return None, outbound_intf

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

    def show_vrf_config(self, vrf_name):
        ''' this method will verify if nbma address
            is reachable through a vrf '''
        bgp_logger.info('show_vrf_config() method')
        self.command = ('sh ip vrf | i ' + vrf_name)
        intf_id_pat = re.compile(r'(?:%s\s+\d+\:\d+\s+)(\S+)' % vrf_name)
        output = self.run_cisco_commands()
        intf_outbound = False
        for line in output:
            if intf_id_pat.search(line):
                intf_outbound = intf_id_pat.search(line).group(1)
                bgp_logger.info('INT OUTBOUND: %s' % intf_outbound)
                return intf_outbound
        if not intf_outbound:
            return False

    def show_intf_desciption(self, interface_id):
        ''' This method will extract interface description
            if there's a circuit ID it can be used to open
            a carrier ticket '''
        bgp_logger.info('show_interface_desciption() method')
        self.command = 'show run int ' + interface_id + ' | i description'
        output = self.run_cisco_commands()
        description = False
        int_desc_pattern = re.compile(r'(?:description\s+)(.+)')
        for line in output[1:]:
            if int_desc_pattern.search(line):
                description = int_desc_pattern.search(line).group(1)
                return description
        if not description:
            return False

    def ping_through_vrf(self, vrf_name, telco_end_ip):
        ''' this method will ping nbma end point ip address
            through vrf to test carrier connectivity '''
        bgp_logger.info('ping_through_vrf() method')
        self.command = "ping vrf " + vrf_name + " " + telco_end_ip
        output = self.run_cisco_commands()
        return output

    def ping_through_telco(self, nbma_end_ip):
        ''' this method will ping nbma end point ip address to test
            ip connectivity '''
        bgp_logger.info('ping_through_telco() method')
        self.command = "ping " + nbma_end_ip
        output = self.run_cisco_commands()
        return output

    def vrf_in_tunnel(self, tunnel_id):
        '''
        Verify if tunnel is configured under a vrf
        '''
        bgp_logger.info('show_config_tunnel() method')
        vrf_pat = re.compile(r'(?:tunnel\s+vrf\s+)(\S+)')
        self.command = "show run int " + tunnel_id + " | inc vrf"
        output = self.run_cisco_commands()
        vrf_name = False
        for line in output:
            if vrf_pat.search(line):
                vrf_name = vrf_pat.search(line).group(1)
        if vrf_name:
            return vrf_name
        else:
            return False

    def vrf_in_interface(self, interface_id):
        '''
        Verify if there's a vrf configured under interface
        to make sure pings to destination IP are successful
        '''
        bgp_logger.info('vrf_in_interface() method')
        vrf_pat = re.compile(r'(?:ip\s+vrf\s+forwarding\s+)(\S+)')
        self.command = "show run int " + interface_id + " | inc vrf"
        output = self.run_cisco_commands()
        vrf_name = False
        for line in output:
            if vrf_pat.search(line):
                vrf_name = vrf_pat.search(line).group(1)
        if vrf_name:
            return vrf_name
        else:
            return False


class Recommendations(object):
    '''
    This class will orchestrate recommendations according
    to a few outputs, bgp neighbor summary and ping results
    '''
    def bgp_neighbor(self, bgp_summary, neighbor_ip):
        bgp_logger.info("bgp_neighbor() method")
        for line in bgp_summary:
            if neighbor_ip in line:
                self._bgp_uptime(line)

    def _bgp_uptime(self, bgp_neighbor_uptime):
        '''
        determine if BGP has flapped in the last 24hrs
        regex: Group(1) = Hrs - Group(2) = Min - Group(3) = Sec
        '''
        bgp_logger.info("_bgp_uptime() method")
        uptime_hours = re.compile(r'(\d{2})(?:\:)(\d{2})(?:\:)(\d{2})')
        uptime_days = re.compile(r'(?:\s+)(\d+\w\d+\w)(?:\s+\d+)$')
        match_hours = uptime_hours.search(bgp_neighbor_uptime)
        match_days = uptime_days.search(bgp_neighbor_uptime)

        if match_days:
            bgp_logger.info("BGP neighbor has been stablised"
                            " for over 24hrs\n%s" % bgp_neighbor_uptime)
        if match_hours:
            hours = int(match_hours.group(1))
            minutes = int(match_hours.group(2))
            seconds = int(match_hours.group(3))
            uptime = match_hours.group(0)
            bgp_logger.info("BGP Neighbor Flapped Recently"
                            " in less than 24hrs\n%s" % bgp_neighbor_uptime)

    def _verify_tunnel_config(self, config_tunnel):
        '''
        if tunnel if not configured properly, alert of a false positive alarm
        '''
        bgp_logger.info("_verify_tunnel_config() method")
        checked = [False, False, False]
        for line in config_tunnel:
            print(line)
            if 'ip nhrp network-id' in line:
                checked[0] = True
            if 'tunnel source' in line:
                checked[1] = True
            if 'tunnel mode' in line:
                checked[2] = True
        if any(checked) == False:
            SystemExit("Tunnel Configuration is Incomplete"
                             "Forward ticket to ECC to confirm")
        if any(checked) == True:
            bgp_logger.info("TUNNEL CONFIGURAITON CHECK: PASS")
            return True


def argument_parser():
    ''' Run argument parser to verify what user wants to do '''
    parser = OptionParser(usage="\nOPTION: %prog -d <ci_name> "
                          "-n <ipAddress>\n\n"
                          "EXAMPLE: bgp -d "
                          "wp-nwk-atm-xr.gpi.remote.binc.net"
                          " -n 8.9.10.11\n\n"
                          "ALSO TO PRINT HELP: %prog "
                          "--help to print this information",
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

    # Initialize class that will run clogin on cisco Devices
    bgp = CiscoCommands(ci_fqdn)

    # find is neighbor IP is managed by CDW
    findstring = RunFindstring(neighbor_ip)
    cdw_managed = findstring.find_managed()
    bgp_logger.info('Neighbor IP ID: %s' % cdw_managed)

    # Verify if device is configured with BGP
    bgp_as = bgp.verify_ip_protocols()

    # initialize vrf_name to None
    vrf_name = None
    if bgp_as:
        # display show ip bgp summary
        bgp_summary = bgp.show_bgp_summary(neighbor_ip)
        verify = Recommendations()
        result_bgp_neighbor = verify.bgp_neighbor(bgp_summary, neighbor_ip)
        
        #Initialize logging class
        query_logging = QueryLogs(ci_fqdn)

        # display show ip cef <IP> 
        nexthop_ip, source_interface = bgp.show_ip_cef(neighbor_ip)
        bgp_logger.info("NEXHOP IP: %s , INTERFACE: %s" %
                        (nexthop_ip, source_interface))
        
        # Verify Tunnel configuration, if this is an incomplete
        # implementation stop the script and notify user
        if 'Tunnel' in source_interface:
            vrf_name = bgp.vrf_in_tunnel(source_interface)
            bgp_logger.info("VRF NAME: %s" % vrf_name)

            if vrf_name:
                tunnel_source_intf = bgp.show_vrf_config(vrf_name)
                bgp_logger.info("TUNNEL SOURCE: %s" % tunnel_source_intf)
                intf_description = bgp.show_intf_desciption(tunnel_source_intf)
                bgp_logger.info("INTF DESCRIPTION: %s" % intf_description)
            
            nexthop_telco = bgp.show_dmvpn_interface(source_interface,
                            neighbor_ip)
            bgp_logger.info("TELCO: %s" % nexthop_telco)

            # show_ip_cef returns 2 values, ignoring nexthop IP
            _, telco_intf = bgp.show_ip_cef(nexthop_telco)
            bgp_logger.info("TELCO INTF: %s" % telco_intf)
            intf_description = bgp.show_intf_desciption(telco_intf)
            bgp_logger.info("INTF DESCRIPTION: %s" % intf_description)
            
            if vrf_name:
                ping_results = bgp.ping_through_vrf(vrf_name, nexthop_telco)
            else:
                ping_results = bgp.ping_through_telco(nexthop_telco)
            bgp_logger.info("PING RESULTS: %s" % ping_results)

            ping = AnalyzePingResults(ping_results)
            ping.anylize_pings()

        else:
            vrf_name = bgp.vrf_in_interface(source_interface)
            bgp_logger.info("VRF NAME: %s" % vrf_name)
            if vrf_name:
                source_intf = bgp.show_vrf_config(vrf_name)
                bgp_logger.info("SOURCE INTERFACE: %s" % tunnel_source_intf)

            intf_description = bgp.show_intf_desciption(source_interface)
            bgp_logger.info("INTF DESCRIPTION: %s" % intf_description)

            if vrf_name:
                ping_results = bgp.ping_through_vrf(vrf_name, neighbor_ip)
            else:
                ping_results = bgp.ping_through_telco(neighbor_ip)
            bgp_logger.info("PING RESULTS: %s" % ping_results)

            ping = AnalyzePingResults(ping_results)
            ping.anylize_pings()

        '''

        verify = Recommendations()
        verify.bgp_neighbor(bgp_summary, neighbor_ip)


        # Query logs, look for interface flaps or BGP State Change entries
        intf_flaps = query_logging.query_lcat_intf_flap(source_interface)
        if intf_flaps:
            for line in intf_flaps:
                print(line)
        else:
            print("NO INTERFACE FLAPS FOUND")
        # Query logs for BGP and neighbor IP state changes
        bgp_logs = query_logging.query_lcat_bgp(neighbor_ip)
        if bgp_logs:
            for line in bgp_logs:
                print(line)
        else:
            print("NO BGP ENTIES FOUND IN THE LOG")
        '''
    else:
        raise SystemExit("This device %s does not run BGP" % ci_fqdn)


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
