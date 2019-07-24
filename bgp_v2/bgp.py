#!/usr/bin/python
from __future__ import print_function
from optparse import OptionParser
from collections import defaultdict
from ecc_libs_py.user_input import VerifyUserInput, RunFindString
import re


# -*- coding: utf-8 -*-
__author__ = "Miguel Bonilla"
__copyright__ = "Copyright 2019, CDW"
__version__ = "2.0"
__maintainer__ = "Miguel Bonilla"
__email__ = "migboni@cdw.com"

'''
This script will help with gathering BGP neighbor information
and extracting MPLS/Carrier interface to open a carrier ticket
if determined that it is needed.
'''

def user_input_checker(input_instance):
    logger.info('user_input_checker() method')
    # lookup ci _name under /etc/hosts file
    etc_stdout = input_instance.verify_etc_hosts()
    # filter findstring output, only get line where ci name is
    if etc_stdout:
        findstr = input_instance.filter_findstring_output(etc_stdout)
        # if multiple lines are returned, generate menu and let
        # user choose appropriate ci name
        if findstr:
            return(input_instance.verify_multiple_entries(findstr))
    else:
        return False


def validate_ci_name(ci_name):
    logger.info('validate_ci_name() method')
    # Verify ci_name is not empty
    input_instance = VerifyUserInput(ci_name)
    # verify ci_name is not empty, if ci_name is empty
    # terminate script
    ci_name_not_empty = input_instance.verify_ci()
    # if ci_name is not empty verify input agains /etc/hosts
    # in BMN
    if ci_name_not_empty:
        ci_name_bmn = user_input_checker(input_instance)
    else:
        ci_name_bmn = False

    if not ci_name_bmn:
        raise SystemExit('Terminating Script!')
    else:
        print("DEVICE NAME VERIFIED OK... PROCEEDING!")
        print(" ")
        return (ci_name_bmn)


def argument_parser():
    logger.info("argument_parser()")
    ''' Run argument parser to verify what user wants to do '''
    parser = OptionParser(usage="\nOPTION: %prog -d <ci_name> "
                          "-n <ipAddress>\n\n"
                          "EXAMPLE: bgp -d "
                          "wp-nwk-atm-xr.gpi.remote.binc.net"
                          " -n 8.9.10.11\n\n"
                          "EXAMPLE: bgp -d "
                          "wp-nwk-atm-xr.gpi.remote.binc.net"
                          " -n 8.9.10.11"
                          " -v VRF-NAME\n\n"
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
    parser.add_option("-v", "--vrf",
                      action="store",
                      dest="vrf_name",help="VRF Name is an optional parameter",)
    (options, args) = parser.parse_args()

    # if ci_name and neighbor_ip were entered, proceed...
    if options.ci_name and options.neighbor_ip:
        # verify ci_name agains /etc/hosts
        ci_name = validate_ci_name(options.ci_name)
        # if no match was found on /etc/hosts
        return(ci_name, options.neighbor_ip)
    else:
        parser.error("You need to provide ci_name and BGP Neighbor"
                     " IP to run this Script\n\n")


if __name__ == '__main__':
    #  bgpInfo -d wp-nwk-atm-xr.gpi.remote.binc.net
    # Initializing Dictionary to Store BGP information
    try:
        from ecc_libs_py.script_logger import Logger
        logger = Logger.logger
        ci_fqdn, neighbor_ip = argument_parser()

    except KeyboardInterrupt:
        raise SystemExit("APPLICATION TERMINATED!")