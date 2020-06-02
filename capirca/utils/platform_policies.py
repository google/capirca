from capirca.lib import aclgenerator
from capirca.lib import arista
from capirca.lib import aruba
from capirca.lib import brocade
from capirca.lib import cisco
from capirca.lib import ciscoasa
from capirca.lib import ciscoxr
from capirca.lib import cloudarmor
from capirca.lib import gce
from capirca.lib import ipset
from capirca.lib import iptables
from capirca.lib import juniper
from capirca.lib import junipersrx
from capirca.lib import naming
from capirca.lib import nftables
from capirca.lib import nsxv
from capirca.lib import packetfilter
from capirca.lib import paloaltofw
from capirca.lib import pcap
from capirca.lib import policy
from capirca.lib import speedway
from capirca.lib import srxlo
from capirca.lib import windows_advfirewall


def GetDefaultPolicyListAndRenderers():
    platforms_pol_data = {
        'juniper': { 
            'policy': False, 
            'renderer': juniper.Juniper
        },
        'cisco': { 
            'policy': False, 
            'renderer': cisco.Cisco
        },
        'ciscoasa': { 
            'policy': False, 
            'renderer': ciscoasa.CiscoASA
        },
        'aruba': { 
            'policy': False, 
            'renderer': aruba.Aruba
        },
        'brocade': { 
            'policy': False, 
            'renderer': brocade.Brocade
        },
        'arista': { 
            'policy': False, 
            'renderer': arista.Arista
        },
        'cloudarmor': { 
            'policy': False, 
            'renderer': cloudarmor.CloudArmor
        },
        'gce': { 
            'policy': False, 
            'renderer': gce.GCE
        },
        'ipset': { 
            'policy': False, 
            'renderer': ipset.Ipset
        },
        'iptables': { 
            'policy': False, 
            'renderer': iptables.Iptables
        },
        'speedway': { 
            'policy': False, 
            'renderer': speedway.Speedway
        },
        'nsx': { 
            'policy': False, 
            'renderer': nsxv.Nsxv
        },
        'pcap_accept': { 
            'policy': False, 
            'renderer': pcap.PcapFilter
        },
        'pcap_deny': { 
            'policy': False, 
            'renderer': 
                lambda policy, info: pcap.PcapFilter(policy, info, invert=True)
        },
        'packetfilter': { 
            'policy': False, 
            'renderer': packetfilter.PacketFilter
        },
        'srx': { 
            'policy': False, 
            'renderer': junipersrx.JuniperSRX
        },
        'srxlo': { 
            'policy': False, 
            'renderer': srxlo.SRXlo
        },
        'nftables': { 
            'policy': False, 
            'renderer': nftables.Nftables
        },
        'windows_advfirewall': { 
            'policy': False, 
            'renderer': windows_advfirewall.WindowsAdvFirewall
        },
        'ciscoxr': { 
            'policy': False, 
            'renderer': ciscoxr.CiscoXR
        },
        'paloalto': { 
            'policy': False, 
            'renderer': paloaltofw.PaloAltoFW
        },
    }

    return platforms_pol_data
