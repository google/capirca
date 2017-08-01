firewall {
    family inet {
        replace:
        /*
        ** $Id:$
        ** $Date:$
        ** $Revision:$
        **
        ** this is a sample edge input filter that generates
        ** multiple output formats.
        */
        filter edge-inbound {
            interface-specific;
            /*
            ** this is a sample edge input filter with a very very very long and
            ** multi-line comment that
            ** also has multiple entries.
            */
            term deny-from-bogons {
                from {
                    source-address {
                        0.0.0.0/8;
                        192.0.0.0/24;
                        192.0.2.0/24;
                        198.18.0.0/15;
                        198.51.100.0/24;
                        203.0.113.0/24;
                        /* IP multicast */
                        224.0.0.0/4;
                        240.0.0.0/4;
                    }
                }
                then {
                    discard;
                }
            }
            term deny-from-reserved {
                from {
                    source-address {
                        /* reserved */
                        0.0.0.0/8;
                        /* non-public */
                        10.0.0.0/8;
                        /* Shared Address Space */
                        100.64.0.0/10;
                        /* loopback */
                        127.0.0.0/8;
                        /* special use IPv4 addresses - netdeploy */
                        169.254.0.0/16;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                        /* IP multicast */
                        224.0.0.0/3;
                    }
                }
                then {
                    discard;
                }
            }
            term deny-to-rfc1918 {
                from {
                    destination-address {
                        /* non-public */
                        10.0.0.0/8;
                        /* non-public */
                        172.16.0.0/12;
                        /* non-public */
                        192.168.0.0/16;
                    }
                }
                then {
                    discard;
                }
            }
            term permit-mail-services {
                from {
                    destination-address {
                        /* Example mail server 1, Example mail server 2 */
                        200.1.1.4/31;
                    }
                    protocol tcp;
                    destination-port [ 25 465 587 995 ];
                }
                then accept;
            }
            term permit-web-services {
                from {
                    destination-address {
                        /* Example web server 1 */
                        200.1.1.1/32;
                        /* Example web server 2 */
                        200.1.1.2/32;
                    }
                    protocol tcp;
                    destination-port [ 80 443 ];
                }
                then accept;
            }
            term permit-tcp-established {
                from {
                    destination-address {
                        /* Example web server 1 */
                        200.1.1.1/32;
                        /* Example web server 2, Example company NAT address */
                        200.1.1.2/31;
                        /* Example mail server 1, Example mail server 2 */
                        200.1.1.4/31;
                    }
                    protocol tcp;
                    tcp-established;
                }
                then accept;
            }
            term permit-udp-established {
                from {
                    destination-address {
                        /* Example web server 1 */
                        200.1.1.1/32;
                        /* Example web server 2, Example company NAT address */
                        200.1.1.2/31;
                        /* Example mail server 1, Example mail server 2 */
                        200.1.1.4/31;
                    }
                    protocol udp;
                    source-port 1024-65535;
                }
                then accept;
            }
            term default-deny {
                then {
                    discard;
                }
            }
        }
    }
}
firewall {
    family inet {
        replace:
        /*
        ** $Id:$
        ** $Date:$
        ** $Revision:$
        **
        ** this is a sample output filter
        */
        filter edge-outbound {
            interface-specific;
            term deny-to-bad-destinations {
                from {
                    destination-address {
                        /* reserved */
                        0.0.0.0/8;
                        /* non-public */
                        10.0.0.0/8;
                        /* Shared Address Space */
                        100.64.0.0/10;
                        /* loopback */
                        127.0.0.0/8;
                        /* special use IPv4 addresses - netdeploy */
                        169.254.0.0/16;
                        /* non-public */
                        172.16.0.0/12;
                        192.0.0.0/24;
                        192.0.2.0/24;
                        /* non-public */
                        192.168.0.0/16;
                        198.18.0.0/15;
                        198.51.100.0/24;
                        203.0.113.0/24;
                        /* IP multicast */
                        224.0.0.0/3;
                    }
                }
                then {
                    discard;
                }
            }
            term default-accept {
                then accept;
            }
        }
    }
}
