#!/usr/bin/python
from __future__ import print_function
from optparse import OptionParser
from collections import defaultdict
import subprocess
import re
# import datetime
import logging


class VerifyUserInput(object):
    """
    Verify User input: ci_name against the /etc/host file.
    return ci_name + domain name:
    wp-nwk-atm-xr.gpi.remote.binc.net
    """
    def __init__(self, ci_name=None):
        self.ci_name = ci_name
        self.verified = False
        self.stdout = None
        self.ci_list = []
        self.ci_count = []

    def verify_ci(self):
        bgp_logger.info('verify_ci() method')
        if self.ci_name is None:
            print("YOU DIDN'T INCLUDE DEVICE NAME!")
            return False
        else:
            return True

    def verify_etc_hosts(self):
        ''' run cat /etc/hosts and get list of devices '''
        # declaring function scope variable
        bgp_logger.info('verify_etc_hosts() method')
        print(" ")
        print("I AM CHECKING THE CI NAME AGAINST \"/etc/hosts\" ENTRIES "
              "ON THIS BMN")
        print(" ")
        try:
            proc = subprocess.Popen(
                ['cat', '/etc/hosts'], stdout=subprocess.PIPE)
            grep = subprocess.Popen(
                ['grep', self.ci_name],
                stdin=proc.stdout, stdout=subprocess.PIPE)

            self.stdout = grep.communicate()[0]
            self.stdout = self.stdout.split('\n')
            bgp_logger.info('SELF.STDOUT_FINDSTRING: %s' % self.stdout)
        except Exception as err:
            bgp_logger.info(err)
            raise SystemExit(
                "I am not able to find your BGP ROUTER on this BMN\n")
        # Initialize the verified variable if ci_name is not found in
        # /etc/hosts script will exit
        self.stdout = self.filter_findstring_output()
        self.stdout = self.verify_multiple_entries()

        # verified will be None if no FQDN was found
        if not self.stdout:
            print("I cannot find %s as a managed device"
                  " in this BMN" % self.ci_name)
            return False
        else:
            # because self.stdout was turned into a list, it now needs to
            # return the single item stripped out of list
            bgp_logger.info('RETURN FROM ETC/HOST %s' % self.stdout)
            print("!")
            print("I FOUND A VALID ENTRY! ...")
            print("!")
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
                    selection = int(raw_input("Choice# "))
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
                if len(self.ci_count) == 0:
                    return False
                else:
                    try:
                        return self.ci_count[0]
                    except IndexError:
                        return False
            else:
                return self.ci_count

    def print_menu(self):
        '''
        print menu if multiple devices with similar name
        '''
        print("I found MULTIPLE entries with similar name,\n"
              "Choose which CI you want to run this script on,\n"
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
        host_pattern = re.compile(r'(%s)' % self.ci_name, re.IGNORECASE)
        for line in self.stdout:
            bgp_logger.info('LINE: %s' % line)
            if host_pattern.search(line):
                self.verified = True
                bgp_logger.info("VERIFIED: %s" % self.verified)
                if len(line.split()) == 3:
                    bgp_logger.info(line.split()[1])
                    ci_fqdn = line.split()[1]
                    filtered.append(ci_fqdn)
        bgp_logger.info("FILTERED FINDSTRING: %s" % filtered)
        return filtered

    def test_connectivity(self):
        '''
        Test if device entered is down. I will ping twice
        '''
        bgp_logger.info('test_connectivity() method')
        try:
            ping_subprocess = subprocess.Popen(
                ['ping', '-c 2', self.ci_name], stdout=subprocess.PIPE)
            ping = ping_subprocess.communicate()[0]
            ping = ping.split('\n')
        except Exception as err:
            bgp_logger.info("ERROR: %s" % err)
            raise SystemExit(
                "I WAS NOT ABLE TO TEST CONNECTIVITY TO: %s\n"
                "PYTHON SUBPROCESS HAS FAILED!")
        connectivity = self._verify_ping_results(ping)
        if connectivity:
            return True

    def _verify_ping_results(self, ping):
        '''
        run regex against the ping output
        '''
        bgp_logger.info('_verify_ping_results() method')
        success_pat = re.compile('''(?:\d+\spackets\stransmitted\,\s+)
            (\d+)(?:\s+received\,.+)''', re.VERBOSE)
        # packet_count will be False as default
        packet_count = False
        for line in ping:
            bgp_logger.info("CONNECTIVITY TEST: %s" % line)
            if success_pat.search(line):
                bgp_logger.info('PING: FOUND A MATCH')
                packet_count = int(success_pat.search(line).group(1))
                if packet_count > 0:
                    # connectivity test pass, return TRUE
                    bgp_logger.info("PACKET_COUNT: %s" % packet_count)
                    return True
        # this should also stop script if packet_count is 0
        if not packet_count:
            raise SystemExit("\nI CANNOT ESTABLISH CONNECTIVITY!\n"
                             "THIS DEVICE: %s SEEMS TO BE DOWN.\n"
                             % self.ci_name)


class RunFindstring(object):
    '''
    Run findstring on neighbor IP to verify if it is managed by CDW
    '''
    def __init__(self, neighbor_ip=None):
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
                proc = subprocess.Popen(['findstring', '-d',
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
        bgp_logger.disabled = True

        # self.file_log = logging.FileHandler(log_filename)
        # self.file_log.setLevel(logging.INFO)

        streamLog = logging.StreamHandler()
        streamLog.setLevel(logging.INFO)

        formatter = logging.Formatter('L:%(lineno)d - %(asctime)s - '
                                      '%(levelname)s - %(message)s')
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
                ['grep', neighbor_ip + ' '], stdin=grep2_bgp.stdout,
                stdout=subprocess.PIPE)
            stdout = grep3_neighbor.communicate()[0]
            stdout = stdout.split('\n')
            for line in stdout:
                if "BGP" in line:
                    if len(stdout) > 15:
                        return stdout[-15:]
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
    def __init__(self, ping_results=False):
        self.ping_results = ping_results

    def anylize_pings(self):
        # below regex pattern
        # (?:Success\s+rate\s+is\s)(\d+)(?:\s+percent\s+)(\((\d+)\/(\d)\))
        bgp_logger.info('anylize_pings() method')
        srate_pat = re.compile('''(?:Success\s+rate\s+is\s)
                  (\d+)(?:\s+percent\s+)(\((\d+)\/(\d)\))''', re.VERBOSE)

        if self.ping_results:
            for line in self.ping_results:
                if srate_pat.match(line):
                    success_rate = int(srate_pat.match(line).group(1))
                    # pings_sent = srate_pat.match(line).group(4)
                    # success_pings = srate_pat.match(line).group(3)
            if success_rate == 0:
                print(" ")
                print("Open a CARRIER TICKET."
                      " Circuit is not forwarding Traffic")
                print(" ")
            if success_rate < 100:
                print(" ")
                print("There are some PACKET LOSS, "
                      "This looks like a TELCO ISSUE\n")
                print(" ")
            if success_rate == 100:
                print(" ")
                print("Ping results show Circuit is OK")
                print(" ")
        else:
            print(" ")
            print("Ping Results Were Not Received")
            print(" ")


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
        bgp_admin = False
        for line in output:
            if bgp_as_pattern.search(line):
                bgp_admin = bgp_as_pattern.search(line).group(1)
        return bgp_admin

    def show_multilink_members(self):
        '''
        this method returns a dictionary of interfaces along with
        state and protocol status UP/DOWN.
        '''
        bgp_logger.info('show_multilink_members() method')
        self.command = "show ppp multilink"
        output = self.run_cisco_commands()

        t1_members_pat = re.compile(
            r'(?:Member links:\s+)(\d)(?:\s+active,\s+)(\d)(?:\sinactive\s)')
        serial_short_pat = re.compile(r'(Se\S+)(?:,\s)')

        # dictonary to store multilink member interfaces and status
        multilink_dict = lambda: defaultdict(multilink_dict)
        multilink_members = multilink_dict()
        multilink_members = {"interface": {}}
        multilink_members.update({"active": ''})
        multilink_members.update({"inactive": ''})
        for line in output:
            bgp_logger.info('INT: %s' % line)
            if t1_members_pat.search(line):
                active = t1_members_pat.search(line).group(1)
                multilink_members["active"] = active
                inactive = t1_members_pat.search(line).group(2)
                multilink_members["inactive"] = inactive
            if serial_short_pat.search(line):
                intf_id = serial_short_pat.search(line).group(1)
                multilink_members["interface"].update({intf_id: {}})
        multilink_members = self._show_alarms_T1(multilink_members)
        return dict(multilink_members)

    def _show_alarms_T1(self, multilink_members):
        '''
        verify if there's any alarms on T1
        '''
        bgp_logger.info('_show_controllers_T1() method')
        print("")
        print("Looking for alarms on T1s, this may take a few seconds")
        controller_pat = re.compile(r'(?:[S|s]e(?:rial)?)(\S+)(?::\d)')
        for T1s in multilink_members["interface"].keys():
            bgp_logger.info('T1s: %s' % T1s)
            print("I am looking on: %s" % T1s)
            # contoller_pat will extract the port number out of Serial
            # interface
            if controller_pat.search(T1s):
                multilink_members["interface"][T1s].update({"alarms": []})
                multilink_members["interface"][T1s].update(
                    {"description": ""})
                # show controllers T1 0/1/1 brief | i Description|State:
                # if regex fails to find value it will insert None
                # to description and alarms key values
                try:
                    self.command = "show controllers T1 "
                    # added parenthesis to split longer than 79 characters
                    self.command += (controller_pat.search(T1s).group(1) +
                                     " brief")
                    self.command += " | i Description|State:"
                    output = self.run_cisco_commands()
                except TypeError:
                    # assign default values if regex cannot be processed
                    # of if returns blank
                    (multilink_members["interface"][T1s]
                        ["description"]) = "Not Able to Retrieve"
                    (multilink_members["interface"][T1s]
                        ["alarms"]) = "Not able to Retrieve"
                # if try above succeeds it will assign the Description
                # and alamrs values to dictionary
                for line in output:
                    bgp_logger.info('LINE: %s' % line)
                    if line:
                        if "Description" in line:
                            (multilink_members["interface"][T1s]
                                ["description"]) = line
                        if "AIS" in line:
                            (multilink_members["interface"]
                                [T1s]["alarms"]) = line
                    else:
                        (multilink_members["interface"][T1s]
                            ["description"]) = "Not able to retrieve"
                        (multilink_members["interface"]
                            [T1s]["alarms"]) = "Not able to retrieve"
        return multilink_members

    def clean_clogin_output(self, clogin_output):
        bgp_logger.info('clean_clogin_output() method')
        ''' remove prompt output from clogin output '''
        # default values
        start = False
        end = False
        if clogin_output:
            for index, line in enumerate(clogin_output):
                if self.command in line:
                    start = index
                if 'exit' in line:
                    end = index
            if start:
                return clogin_output[start:end]
            if end:
                return clogin_output[:end]
            else:
                return clogin_output
        else:
            return False

    def run_cisco_commands(self):
        bgp_logger.info('run_cisco_commands() method')
        ''' Run clogin to retrieve command information
        from device '''
        bgp_logger.info('COMMAND: %s' % self.command)
        try:
            clogin_process = subprocess.Popen(['sudo', '-u', 'binc',
                                               '/opt/sbin/clogin',
                                               '-c', self.command,
                                              self.ci_name],
                                              stdout=subprocess.PIPE)
            clogin_output = clogin_process.communicate()[0]
            clogin_output = clogin_output.split('\r\n')
            return self.clean_clogin_output(clogin_output)
            # return clogin_output
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
        if output:
            print("!")
            print('BGP SUMMARY INFORMATION:')
            print("!")
            for line in output[1:]:
                print(line)
            print(" ")
            neighbor_summary = False
            # add a space at the end of IP address to get exact match
            ip_address = ip_address + ' '

            # Verify show ip bgp summary return a False or
            # the information that is needed.
            for line in output:
                if ip_address in line:
                    neighbor_summary = line
            if neighbor_summary:
                bgp_logger.info('BGP SUMMARY: %s' % neighbor_summary)
                return neighbor_summary
            else:
                return False
        else:
            return False     # If BGP Summary Output returns False or Empty

    def show_ip_cef(self, ip_address, vrf_name=False):
        '''
        get vrf information, if vrf exists then use appropriate command
        '''
        bgp_logger.info('show_ip_cef() method')
        if vrf_name:
            self.command = "show ip cef vrf " + vrf_name + " " + ip_address
        else:
            self.command = 'show ip cef ' + ip_address
        output = self.run_cisco_commands()
        cef_interface_pattern = re.compile(
            r'(?:\s+)(\S+)(?:\s+)([MTGESC]\S+)$')

        ip_pattern = re.compile(r'(\d+\.\d+\.\d+.\d+)')

        for line in output:
            if cef_interface_pattern.search(line):
                gateway_ip = cef_interface_pattern.search(line).group(1)
                outbound_intf = cef_interface_pattern.search(line).group(2)

        if ip_pattern.search(gateway_ip):
            return gateway_ip, outbound_intf
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
        intf_id_pat = re.compile(r'(?:\s+)(\S+)$')
        output = self.run_cisco_commands()
        intf_outbound = False
        for line in output[1:]:
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

    def ping_through_isp(self, nbma_end_ip):
        ''' this method will ping nbma end point ip address to test
            ip connectivity '''
        bgp_logger.info('ping_through_isp() method')
        self.command = "ping " + nbma_end_ip
        output = self.run_cisco_commands()
        return output

    def vrf_in_tunnel(self, tunnel_id):
        '''
        Verify if tunnel is configured under a vrf
        '''
        bgp_logger.info('vrf_in_tunnel() method')
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
    def __init__(self, neighbor_ip, bgp_summary):
        self.neighbor_ip = neighbor_ip
        self.bgp_summary = bgp_summary

    def bgp_neighbor_output(self):
        '''
        determine if BGP has flapped in the last 24hrs
        regex: Group(1) = Hrs - Group(2) = Min - Group(3) = Sec
        '''
        bgp_logger.info("bgp_neighbor_output() method")
        uptime_hours_minutes = re.compile(r'(\d{2})(?:\:)(\d{2})(?:\:)(\d{2})')
        uptime_days = re.compile(r'(?:\s+)(\d+\w\d+\w)(?:\s+\d+)$')
        uptime_minutes = re.compile(r'(?:00)(?:\:)(\d{2})(?:\:)(\d{2})')
        bgp_state = re.compile(r'(?:\s+)(\S+)$')
        is_digit = re.compile(r'(\d+)')

        # pre-define matches
        match_hours = False
        match_days = False
        match_state = False
        match_minutes = False
        # match regex to deteremine BGP state
        match_hours = uptime_hours_minutes.search(self.bgp_summary)
        match_days = uptime_days.search(self.bgp_summary)
        match_minutes = uptime_minutes.search(self.bgp_summary)
        match_state = bgp_state.search(self.bgp_summary).group(0)
        bgp_logger.info("BGP State: %s" % match_state)

        # look for uptime greater than 1 hr
        if match_hours:
            hours = int(match_hours.group(1))
            bgp_logger.info("HOURS:  %s" % hours)
            hrs_minutes = int(match_hours.group(2))
            bgp_logger.info("MINUTES: %s" % hrs_minutes)
        else:
            hours = False
        # look for uptime with day or weeks format
        if match_days:
            days = match_days.group(1)
        else:
            days = False
        # look for uptime with 00 hrs and minutes greater or equal to 00
        if match_minutes:
            minutes = int(match_minutes.group(1))
            seconds = int(match_minutes.group(2))
        else:
            minutes = False

        # If PfxRcd is a digit other than a string BGP is down
        # BGP when UP usually received prefixes so it will show digits
        #  State/PfxRcd
        #     1550
        if is_digit.search(match_state):
            state_PfxRcd = is_digit.search(match_state).group(0)
        else:
            state_PfxRcd = False

        if state_PfxRcd:
            # BGP uptime is weeks or days
            if days:
                print("BGP Has been ESTABLISHED for: %s" % days)
                print("It is safe to close this ticket.\n"
                      "Look for any other tickets opened for remote device"
                      " if managed by CDW. Hostname printed above!\n"
                      "If there are tickets on that device, run "
                      "this script on it to verify circuit is stable.\n")
            # BGP uptime is more than or equal to 1hr
            if hours:
                if hours >= 2:
                    print("BGP HAS STOPPED FLAPPING AND IT LOOKS STABLE.")
                    print(" ")
                    print("BGP Flapped %shr(s) and %smin(s) ago" %
                          (hours, hrs_minutes))
                    print("================================================="
                          "==========")
                    print("Are there more instances of this incident?\n"
                          "It's time to correlate and look for any tickets "
                          "opened for the remote device if managed by CDW. "
                          "Printed above!\n"
                          "If there are interfaces going UP/DOWN it must be"
                          " repoted to Telco.")
                    print("================================================="
                          "==========")
                    print(" ")
                if hours < 2:
                    print("IT LOOKS LIKE CONNECTIVITY IS NOT STABLE")
                    print(" ")
                    print("BGP Flapped %shr and %smin ago" %
                          (hours, hrs_minutes))
                    print("================================================="
                          "==========")
                    print("Are there more instances of this incident?\n"
                          "I advise you to report to the carrier.\n"
                          "Also run this script on the remote device if "
                          "managed by CDW. Printed above!\n"
                          "Look for any tickets related to remote device"
                          " and associate that ticket to this one to be"
                          " worked as related events.")
                    print("================================================="
                          "==========")
                    print(" ")
            # BGP uptime is only minutes
            if minutes:
                print("THERE ARE SOME CONCERNS ABOUT CIRCUIT STABILITY")
                print(" ")
                print("BGP Flapped %s minutes and %ssecs ago" %
                      (minutes, seconds))
                print("====================================================="
                      "======")
                print("Are there more instances of this incident?\n"
                      "I advise you to report to the carrier.\n"
                      "Also run this script on the remote device if "
                      "managed by CDW. Printed above!\n"
                      "Look for any tickets related to remote device"
                      " and associate that ticket to\n"
                      "this one to be worked as related events.")
                print("====================================================="
                      "======")
                print(" ")
        else:
            # BGP must be down if 'PfxRcd' is not a digit
            print(" ")
            print("BGP Session is NOT Established.\n"
                  "OPEN A CARRIER TICKET!")
        print(" ")
        print("NEIGHBOR <<< %s >>> INFORMATION:" % neighbor_ip)
        print("============================================")
        print(self.bgp_summary)
        print("============================================")
        print(" ")

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
        if any(checked) is False:
            SystemExit("Tunnel Configuration is Incomplete"
                       "Forward ticket to ECC to confirm")
        if any(checked) is True:
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

        # verify ci_name is not empty
        ci_name_not_empty = user_input.verify_ci()
        if ci_name_not_empty:
            ci_name_bmn = user_input.verify_etc_hosts()
        else:
            ci_name_bmn = False

        if not ci_name_bmn:
            raise SystemExit('Terminating Script!')
        else:
            return (ci_name_bmn, options.neighbor_ip)
    else:
        parser.error("You need to provide ci_name and BGP Neighbor"
                     " IP to run this Script\n\n")


def bgp_orchestrator(ci_fqdn, neighbor_ip):
    bgp_logger.info('bgp_orchestrator() method')

    # Initialize class that will run clogin on cisco Devices
    bgp = CiscoCommands(ci_fqdn)

    # find is neighbor IP is managed by CDW
    print("CHECKING ON NEIGHBOR IP ADDRESS: %s\n" % neighbor_ip)

    findstring = RunFindstring(neighbor_ip)
    cdw_managed = findstring.find_managed()

    if cdw_managed:
        print("NEIGHBOR IP ADDRESS: %s,"
              " IS MANAGED BY CDW ON THIS BMN, NAME: %s\n" % (neighbor_ip,
                                                              cdw_managed))
        bgp_logger.info('Neighbor IP ID: %s' % cdw_managed)
    else:
        print("NEIGHBOR IP ADDRESS: %s IS NOT MANAGED BY CDW ON THIS BMN\n" %
              neighbor_ip)

    # Verify Connectivity to device, if no connectivity stop the script
    print("I NEED TO VERIFY CONNECTIVITY TO: %s" % ci_fqdn)
    ping_test = VerifyUserInput(ci_fqdn)
    ping = ping_test.test_connectivity()
    if ping is True:
        print(" CONNECTIVITY IS \"OK\"...\n")

    # Verify if device is configured with BGP
    bgp_as = bgp.verify_ip_protocols()

    # initialize vrf_name to None
    vrf_name = False
    if bgp_as:
        # run show ip bgp summary command against device
        bgp_summary = bgp.show_bgp_summary(neighbor_ip)
        if bgp_summary:
            verify = Recommendations(neighbor_ip, bgp_summary)
            verify.bgp_neighbor_output()
        else:
            print("I am not able to retreive 'show ip bgp summary'"
                  " information.")

        # Initialize logging class
        query_logging = QueryLogs(ci_fqdn)

        # display show ip cef <IP>
        gateway_ip, cef_interface = bgp.show_ip_cef(neighbor_ip)
        bgp_logger.info("NEXHOP IP: %s , INTERFACE: %s" %
                        (gateway_ip, cef_interface))

        # Verify Tunnel configuration, if this is an incomplete
        # implementation stop the script and notify user
        if 'Tunnel' in cef_interface:
            # print tunnel interface associated to this BGP neighbo_ip
            print()
            print("Associated Tunnel Interface: %s" % cef_interface)

            # run dmvpn command to get tunnel destination telco ip
            nexthop_isp = bgp.show_dmvpn_interface(cef_interface,
                                                   neighbor_ip)
            bgp_logger.info("TELCO IP: %s" % nexthop_isp)

            # get tunnel vrf name if configured
            vrf_name = bgp.vrf_in_tunnel(cef_interface)
            bgp_logger.info("VRF NAME: %s" % vrf_name)

            if vrf_name:
                # run vrf against the vrf and telco ip
                gateway_ip, cef_interface = bgp.show_ip_cef(
                    neighbor_ip, vrf_name)
                bgp_logger.info("GATEWAY: %s , INTERFACE: %s" %
                                (gateway_ip, cef_interface))
                print()
                print("ISP/Telco Interface associated with"
                      " this BGP Peering: %s" % cef_interface)
                intf_description = bgp.show_intf_desciption(cef_interface)
                bgp_logger.info("ISP DESC: %s" % intf_description)
                print(" ")
                if not intf_description:
                    intf_description = "Not Found"
                print("ISP Interface description: %s" %
                      intf_description)
            else:
                # run pings against the vrf and telco ip
                gateway_ip, cef_interface = bgp.show_ip_cef(neighbor_ip)
                intf_description = bgp.show_intf_desciption(cef_interface)
                if not intf_description:
                    intf_description = "Not Found"
                bgp_logger.info("ISP DESC: %s" % intf_description)

            if nexthop_isp:
                if vrf_name:
                    # ping accross ISP network
                    ping_results = bgp.ping_through_vrf(vrf_name, nexthop_isp)
                else:
                    ping_results = bgp.ping_through_isp(nexthop_isp)
                bgp_logger.info("PING RESULTS: %s" % ping_results)
                print(" ")
                print("PING RESULTS:")
                for line in ping_results:
                    print(line)
                print(" ")
                # analyze ping results
                ping = AnalyzePingResults(ping_results)
                ping.anylize_pings()
            else:
                print("\n")
                print("I can't find CARRIER IP ADDRESS, "
                      "Verify Neighbor IP is correct an run"
                      "this script again!")
                print("\n")
                print("Terminating this Script!")
                print("\n")
                raise SystemExit("--END--\n")
        else:
            print()
            print("Associated Interface with this BGP Peering: %s" %
                  cef_interface)
            vrf_name = bgp.vrf_in_interface(cef_interface)
            bgp_logger.info("VRF NAME: %s" % vrf_name)

            if vrf_name:
                print()
                print("There's a VRF:{ %s } associated to interface: %s" %
                      (vrf_name, cef_interface))
                gateway_ip, cef_interface = bgp.show_ip_cef(
                    neighbor_ip, vrf_name)
                bgp_logger.info("GATEWAY: %s , INTERFACE: %s" %
                                (gateway_ip, cef_interface))
                intf_description = bgp.show_intf_desciption(cef_interface)
                bgp_logger.info("ISP DESC: %s" % intf_description)
                print(" ")
                if not intf_description:
                    intf_description = "Not Found"
                print("ISP/Telco Interface description: %s" %
                      intf_description)
            else:
                # run pings against the vrf and telco ip
                gateway_ip, cef_interface = bgp.show_ip_cef(neighbor_ip)
                # if Multilink interface, the script is going to pull the
                # member interfaces to retreive individual status UP or
                # alarms
                if 'Multilink' in cef_interface:
                    # multilink = MultilinkCheck(cef_interface)
                    bgp_logger.info("MULTILINK: %s" % cef_interface)
                    multilink_members_dict = bgp.show_multilink_members()
                    if int(multilink_members_dict["inactive"]) > 0:
                        print("!")
                        print("I found %s T1(s) inactive\n"
                              "This needs to be verified a little more.\n"
                              "I suggest open a ticket with the carrier.\n!" %
                              multilink_members_dict["inactive"])
                    if multilink_members_dict["active"]:
                        print("")
                        print("")
                        print("All members of the Multilink are Active\n"
                              "check for ALARMS in the summary below.")
                    print("")
                    print("Summary Multilink State: ")
                    for interfaces in multilink_members_dict["interface"]:
                        print("- %s %s\nALARMS: %s" %
                              (interfaces,
                               (multilink_members_dict["interface"]
                                [interfaces]["description"]),
                               (multilink_members_dict["interface"]
                                [interfaces]["alarms"])))
                intf_description = bgp.show_intf_desciption(cef_interface)
                bgp_logger.info("ISP DESC: %s" % intf_description)
                print(" ")
                if not intf_description:
                    intf_description = "Not Found"
                print("ISP/Telco Interface description: %s" %
                      intf_description)

            if vrf_name:
                ping_results = bgp.ping_through_vrf(vrf_name, neighbor_ip)
            else:
                ping_results = bgp.ping_through_isp(neighbor_ip)
            bgp_logger.info("PING RESULTS: %s" % ping_results)

            print()
            print("PING RESULTS:")
            for line in ping_results:
                print(line)
            # analyze ping results and look for packet loss of failed ping
            ping = AnalyzePingResults(ping_results)
            ping.anylize_pings()

        # Query logs, look for interface flaps or BGP State Change entries
        intf_flaps = query_logging.query_lcat_intf_flap(cef_interface)
        if intf_flaps:
            print("This circuit has been flapping and it has to be"
                  " reported to Carrier.")
            for line in intf_flaps:
                print(line)
        else:
            print(" ")
            print("NO INTERFACE FLAPS FOUND")
        # Query logs for BGP and neighbor IP state changes
        bgp_logs = query_logging.query_lcat_bgp(neighbor_ip)
        if bgp_logs:
            print(" ")
            print("OPEN A CARRIER TICKET TO REPORT THIS BGP INSTABILITY")
            for line in bgp_logs:
                print(line)
        else:
            print(" ")
            print("NO BGP ENTIES FOUND IN THE LOG")
    else:
        raise SystemExit("BGP is not configured on this device: %s," % ci_fqdn)


if __name__ == '__main__':
    #  bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net
    # Initializing Dictionary to Store BGP information
    try:
        # Initialize logging module
        LoggerClass.logging()

        ci_fqdn, neighbor_ip = argument_parser()

        bgp_orchestrator(ci_fqdn, neighbor_ip)
    except KeyboardInterrupt:
        raise SystemExit("APPLICATION TERMINATED!")
