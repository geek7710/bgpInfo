# bgpInfo

__author__ = "Miguel Bonilla"
__copyright__ = "Copyright 2019, CDW"
__version__ = "1.0"
__maintainer__ = "Miguel Bonilla"
__email__ = "migboni@cdw.com"

The name of this script is '''bgp''' the script is intended to help OAsII and OAsIII quickly determine if there's a BGP Peering issue related to a carrier.
This script will extract Carrier facing interface as well as interface description. Most the time the interface description include the Carrier Circuit ID.
It will ping accross the Carrier to Underlying End IP in case of a Tunnel or the BGP peering if no Tunnel is configured.
If there's a VRF the script will be able to ping across the VRF.
If there's a Multilink Circuit. The script is able to pull the members of the Multilink and check alarm on any one of them. In addition to alarm the script will Warn if a member of the Multilink is down.

