import subprocess

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
