from logger import LoggerClass

LoggerClass.logging()

class RecursiveLookup(object):

    def is_tunnel(self, source_interface):
        if 'Tunnel' in source_interface:
            logger.info('Found a Tunnel Interface')
            nbma_end_ip = self.show_dmvpn_interface(source_interface,
                                                    neighbor_ip)
            logger.info('NBMA IP: %s' % nbma_end_ip)
        else:
            logger.info('Found no Tunnel Interface')
            nbma_end_ip = None

        if nbma_end_ip:
            tunnel_dest_ip, source_interface = self.show_ip_cef(nbma_end_ip)
            logger.info('nexthop_ip %s , source_interface %s' %
                            (nbma_end_ip, source_interface))
        return (nbma_end_ip, source_interface)


class CiscoCommands(RecursiveLookup):
    ''' This class will run any bgp related commands '''

    def __init__(self, ci_name):
        self.ci_name = ci_name
        self.command = None

    def verify_ip_protocols(self):
        ''' This method will verify BGP is configured '''
        logger.info('verify_ip_protocols() method')
        print()
        print("ENTER YOUR RSA PASSCODE IF ASKED FOR IT")
        print()
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
        logger.info('show_multilink_members() method')
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
            logger.info('INT: %s' % line)
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
        logger.info('_show_controllers_T1() method')
        print("")
        print("Looking for alarms on T1s, this may take a few seconds")
        controller_pat = re.compile(r'(?:[S|s]e(?:rial)?)(\S+)(?::\d)')
        for T1s in multilink_members["interface"].keys():
            logger.info('T1s: %s' % T1s)
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
                    logger.info('LINE: %s' % line)
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
        logger.info('clean_clogin_output() method')
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
        logger.info('run_cisco_commands() method')
        ''' Run clogin to retrieve command information
        from device '''
        logger.info('COMMAND: %s' % self.command)
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
        logger.info('show_bgp_neighbor method()')
        self.command = "show ip bgp summary"
        print()
        print("HOLD ON WHILE I RETRIEVE BGP SUMMARY INFORMATION")
        print()
        output = self.run_cisco_commands()
        if output:
            print("------------------------")
            print("BGP SUMMARY INFORMATION:")
            print("------------------------")
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
                logger.info('BGP SUMMARY: %s' % neighbor_summary)
                return neighbor_summary
            else:
                return False
        else:
            return False     # If BGP Summary Output returns False or Empty

    def show_ip_cef(self, ip_address, vrf_name=False):
        '''
        get vrf information, if vrf exists then use appropriate command
        '''
        logger.info('show_ip_cef() method')
        if vrf_name:
            self.command = "show ip cef vrf " + vrf_name + " " + ip_address
        else:
            self.command = 'show ip cef ' + ip_address
        output = self.run_cisco_commands()
        cef_interface_pattern = re.compile(
            r'(?:\s+)(\S+)(?:\s+)([MTGESC]\S+)')

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
        logger.info('show_dmvpn_interface() method')
        self.command = ('show dmvpn interface ' + source_interface +
                        ' | i ' + neighbor_ip + " ")

        dmvpn_output_pattern = re.compile(r'(?:^\s+\d+\s)(\S+)(?:\s+\S+\s+)')
        output = self.run_cisco_commands()
        # initialize tunnel destination IP to False
        nbma_ip = False
        for line in output[1:]:
            if dmvpn_output_pattern.search(line):
                nbma_ip = dmvpn_output_pattern.search(line).group(1)
        return nbma_ip

    def show_dmvpn(self, neighbor_ip):
        ''' Extract dmvpn tunnel(s) configured on the router,
            this will help determine the NBMA address used as tunnel
            destination.'''
        logger.info('show_dmvpn() method')
        self.command = ('show dmvpn')
        dmvpn_interfaces_pat = re.compile(r'(?:[I|i]nterface: )(\S+)(?:,.+)')
        output = self.run_cisco_commands()
        # append Tunnel interfaces found into a list
        tunnels = []
        for line in output[1:]:
            if dmvpn_interfaces_pat.search(line):
                tunnels.append(dmvpn_interfaces_pat.search(line).group(1))
        logger.info(tunnels)
        return tunnels

    def show_vrf_config(self, vrf_name):
        ''' this method will verify if nbma address
            is reachable through a vrf '''
        logger.info('show_vrf_config() method')
        self.command = ('sh ip vrf | i ' + vrf_name)
        intf_id_pat = re.compile(r'(?:\s+)(\S+)$')
        output = self.run_cisco_commands()
        intf_outbound = False
        for line in output[1:]:
            if intf_id_pat.search(line):
                intf_outbound = intf_id_pat.search(line).group(1)
                logger.info('INT OUTBOUND: %s' % intf_outbound)
                return intf_outbound
        if not intf_outbound:
            return False

    def show_intf_desciption(self, interface_id):
        ''' This method will extract interface description
            if there's a circuit ID it can be used to open
            a carrier ticket '''
        logger.info('show_interface_desciption() method')
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
        logger.info('ping_through_vrf() method')
        self.command = "ping vrf " + vrf_name + " " + telco_end_ip
        output = self.run_cisco_commands()
        return output

    def ping_through_isp(self, nbma_end_ip):
        ''' this method will ping nbma end point ip address to test
            ip connectivity '''
        logger.info('ping_through_isp() method')
        self.command = "ping " + nbma_end_ip
        output = self.run_cisco_commands()
        return output

    def vrf_in_tunnel(self, tunnel_id):
        '''
        Verify if tunnel is configured under a vrf
        '''
        logger.info('vrf_in_tunnel() method')
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
        logger.info('vrf_in_interface() method')
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

    def extract_tunnel_destination(self, tunnel_id):
        '''
        In the absense of DMVPN configuration, Tunnel only has
        source IP and destination IP. This method will extract
        that destination IP from the Tunnel Interface
        '''
        logger.info('extract_tunnel_destination()')
        self.command = "show run int " + tunnel_id + " | i destination"
        output = self.run_cisco_commands()
        tunnel_destination_pat = re.compile(
            r'(?:tunnel\s+destination\s+)(\S+)')
        dest_ip = False
        for line in output:
            if tunnel_destination_pat.search(line):
                dest_ip = tunnel_destination_pat.search(line).group(1)
        return dest_ip

    def list_tunnel_interfaces(self):
        '''
        Need to look for Tunnels configured on the router
        this way the script will no run cef but run dmvpn to look
        for the carrier IP
        '''
        logger.info('show_interface_brief()')
        self.command = "show ip int b | i Tunnel"
        tunnel_pat = re.compile(
            r'^(Tunnel\d+)(?:.+)(up|down)(?:\s+)(up|down)')
        output = self.run_cisco_commands()
        # Store tunnel name and state in dictionary
        tunnel_stats = defaultdict(dict)
        for line in output:
            if tunnel_pat.search(line):
                tunnel_id = tunnel_pat.search().group(1)
                tunnel_status = tunnel_pat.search().group(2)
                tunnel_protocol = tunnel_pat.search().group(3)
                tunnel_stats.update({tunnel_id: {}})
                tunnel_stats[tunnel_id].update({'status': tunnel_status})
                tunnel_stats[tunnel_id].update({'protocol': tunnel_protocol})
        return dict(tunnel_stats) if tunnel_stats else False
