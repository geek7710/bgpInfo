import subprocess

class VerifyUserInput(object):
    """
    Verify User input: ci_name against the /etc/host file.
    return ci_name + domain name:
    wp-nwk-atm-xr.gpi.remote.binc.net
    """
    def __init__(self, ci_name=None):
        self.ci_name = ci_name
        self.verified = False
        self.ci_list = []
        self.ci_count = []

    def verify_etc_hosts(self):
        ''' run cat /etc/hosts and get list of devices '''
        # declaring function scope variable
        logger.info('verify_etc_hosts() method')
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

            stdout = grep.communicate()[0]
            stdout = stdout.split('\n')
            logger.info('SELF.STDOUT_FINDSTRING: %s' % stdout)
        except Exception as err:
            logger.info(err)
            raise SystemExit(
                "I am not able to find your BGP ROUTER on this BMN\n")

        # verified will be None if no FQDN was found
        if not stdout:
            print("I cannot find %s as a managed device"
                  " in this BMN" % self.ci_name)
            return False
        else:
            return stdout

    def verify_multiple_entries(self, findstring_output):
        '''
        If multiple devices with similiar name are found,
        prompt user which device is the script going to run on
        '''
        logger.info('verify_multiple_entries() method')
        for line in findstring_output:
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
            logger.info("SELECTION: %s" % self.ci_count[selection])
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

    def filter_findstring_output(self, etc_stdout):
        '''
        filter out unneeded fields and return only log ci_name
        "wp-hauppauge-sw.gpi.remote.hms.cdw.com"
        '''
        filtered = []
        logger.info('filter_findstring_output() methods')
        host_pattern = re.compile(r'(%s)' % self.ci_name, re.IGNORECASE)
        for line in etc_stdout:
            logger.info('LINE: %s' % line)
            if host_pattern.search(line):
                self.verified = True
                logger.info("VERIFIED: %s" % self.verified)
                if len(line.split()) == 3:
                    logger.info(line.split()[1])
                    ci_fqdn = line.split()[1]
                    filtered.append(ci_fqdn)
        logger.info("FILTERED FINDSTRING: %s" % filtered)
        findstring_stdout = filtered
        if not findstring_stdout:
            return False
        else:
            return findstring_stdout

    def test_connectivity(self):
        '''
        Test if device entered is down. I will ping twice
        '''
        logger.info('test_connectivity() method')
        try:
            ping_subprocess = subprocess.Popen(
                ['ping', '-c 2', self.ci_name], stdout=subprocess.PIPE)
            ping = ping_subprocess.communicate()[0]
            ping = ping.split('\n')
        except Exception as err:
            logger.info("ERROR: %s" % err)
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
        logger.info('_verify_ping_results() method')
        success_pat = re.compile('''(?:\d+\spackets\stransmitted\,\s+)
            (\d+)(?:\s+received\,.+)''', re.VERBOSE)
        # packet_count will be False as default
        packet_count = False
        for line in ping:
            logger.info("CONNECTIVITY TEST: %s" % line)
            if success_pat.search(line):
                logger.info('PING: FOUND A MATCH')
                packet_count = int(success_pat.search(line).group(1))
                if packet_count > 0:
                    # connectivity test pass, return TRUE
                    logger.info("PACKET_COUNT: %s" % packet_count)
                    return True
        # this should also stop script if packet_count is 0
        if not packet_count:
            raise SystemExit("\nI CANNOT ESTABLISH CONNECTIVITY!\n"
                             "THIS DEVICE: %s SEEMS TO BE DOWN.\n"
                             % self.ci_name)


class RunFindString(object):
    '''
    Run findstring on neighbor IP to verify if it is managed by CDW
    '''
    def __init__(self, neighbor_ip=None):
        self.neighbor_ip = neighbor_ip
        logger.info('run_findstring() class')

    def find_managed(self):
        '''
        run findstring to verify if neighbor ip address
        is managed by CDW
        '''
        logger.info('find_managed() method')
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
                logger.info(err)
                raise SystemExit(
                    "I am not able to run findstring on this BMN\n")
        # Initialize the verified variable if ci_name is not found in
        # /etc/hosts script will exit
        if stdout:
            return stdout
        else:
            return False

