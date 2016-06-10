firewall {
    family inet {
        replace:
        /*
        ** $Id:$
        ** $Date:$
        ** $Revision:$
        **
        ** Sample Juniper lookback filter
        */
        filter LOOPBACK {
            interface-specific;
            term accept-icmp {
                from {
                    protocol icmp;
                }
                then {
                    count icmp-loopback;
                    policer rate-limit-icmp;
                    accept;
                }
            }
            /*
            ** Allow BGP requests from peers.
            */
            term accept-bgp-requests {
                from {
                    source-prefix-list {
                        configured-neighbors-only;
                    }
                    protocol tcp;
                    destination-port 179;
                }
                then {
                    count bgp-requests;
                    accept;
                }
            }
            /*
            ** Allow inbound replies to BGP requests.
            */
            term accept-bgp-replies {
                from {
                    source-prefix-list {
                        configured-neighbors-only;
                    }
                    protocol tcp;
                    source-port 179;
                    tcp-established;
                }
                then {
                    count bgp-replies;
                    accept;
                }
            }
            /*
            ** Allow outbound OSPF traffic from other RFC1918 routers.
            */
            term accept-ospf {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol ospf;
                }
                then {
                    count ospf;
                    accept;
                }
            }
            term allow-vrrp {
                from {
                    protocol vrrp;
                }
                then {
                    count vrrp;
                    accept;
                }
            }
            term accept-ike {
                from {
                    protocol udp;
                    source-port 500;
                    destination-port 500;
                }
                then {
                    count ipsec-ike;
                    accept;
                }
            }
            term accept-ipsec {
                from {
                    protocol esp;
                }
                then {
                    count ipsec-esp;
                    accept;
                }
            }
            term accept-pim {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol pim;
                }
                then accept;
            }
            term accept-igmp {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol igmp;
                }
                then accept;
            }
            term accept-ssh-requests {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then {
                    count ssh;
                    accept;
                }
            }
            term accept-ssh-replies {
                from {
                    protocol tcp;
                    source-port 22;
                    tcp-established;
                }
                then {
                    count ssh-replies;
                    accept;
                }
            }
            term accept-snmp-requests {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    destination-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol udp;
                    destination-port 161;
                }
                then accept;
            }
            term accept-dns-replies {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    destination-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol udp;
                    source-port 53;
                    destination-port 1024-65535;
                }
                then {
                    count dns-replies;
                    accept;
                }
            }
            term allow-ntp-request {
                from {
                    source-address {
                        /* Example NTP server */
                        10.0.0.1/32;
                        /* Example NTP server */
                        10.0.0.2/32;
                    }
                    destination-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol udp;
                    destination-port 123;
                }
                then {
                    count ntp-request;
                    accept;
                }
            }
            term allow-ntp-replies {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    destination-address {
                        /* Example NTP server */
                        10.0.0.1/32;
                        /* Example NTP server */
                        10.0.0.2/32;
                    }
                    protocol udp;
                    source-port 123;
                    destination-port 1024-65535;
                }
                then {
                    count ntp-replies;
                    accept;
                }
            }
            term allow-radius-replies {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    destination-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol udp;
                    source-port 1812;
                }
                then {
                    count radius-replies;
                    accept;
                }
            }
            term allow-tacacs-requests {
                from {
                    source-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    destination-address {
                        /* Example tacacs server */
                        10.1.0.1/32;
                        /* Example tacacs server */
                        10.1.0.2/32;
                    }
                    protocol tcp;
                    destination-port 49;
                }
                then {
                    count tacacs-requests;
                    accept;
                }
            }
            term allow-tacacs-replies {
                from {
                    source-address {
                        /* Example tacacs server */
                        10.1.0.1/32;
                        /* Example tacacs server */
                        10.1.0.2/32;
                    }
                    destination-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                    protocol tcp;
                    source-port 49;
                    tcp-established;
                }
                then {
                    count tacacs-replies;
                    accept;
                }
            }
            term allow-dns-fragments {
                from {
                    source-address {
                        0.0.0.0/0;
                        /* Example company NAT address */
                        200.1.1.3/32 except;
                    }
                    destination-address {
                        /* IPv4 Anycast */
                        8.8.4.4/32;
                        /* IPv4 Anycast */
                        8.8.8.8/32;
                    }
                    protocol [ tcp udp ];
                    destination-port 53;
                    is-fragment;
                }
                then accept;
            }
            term ratelimit-large-dns {
                from {
                    destination-address {
                        /* IPv4 Anycast */
                        8.8.4.4/32;
                        /* IPv4 Anycast */
                        8.8.8.8/32;
                    }
                    protocol udp;
                    destination-port 53;
                    packet-length 500-5000;
                }
                then {
                    count large-dns-counter;
                    policer large-dns-policer;
                    sample;
                    next term;
                }
            }
            term reject-large-dns {
                from {
                    destination-address {
                        /* IPv4 Anycast */
                        8.8.4.4/32;
                        /* IPv4 Anycast */
                        8.8.8.8/32;
                    }
                    protocol udp;
                    destination-port 53;
                    packet-length 500-5000;
                }
                then {
                    reject;
                }
            }
            term reject-imap-requests {
                from {
                    destination-address {
                        /* Example mail server 1, Example mail server 2 */
                        200.1.1.4/31;
                    }
                    protocol tcp;
                    destination-port 143;
                }
                then {
                    reject tcp-reset;
                }
            }
            term discard-default {
                then {
                    count discard-default;
                    discard;
                }
            }
        }
    }
}
