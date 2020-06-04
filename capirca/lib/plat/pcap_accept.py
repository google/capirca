from capirca.lib import pcap

class PcapAcceptFilter(pcap.PcapFilter):
    SUFFIX = "-accept.pcap"

PLATFORM = "pcap_accept"
RENDERER = PcapAcceptFilter
