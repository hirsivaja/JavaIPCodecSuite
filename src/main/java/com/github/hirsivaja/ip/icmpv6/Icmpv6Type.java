package com.github.hirsivaja.ip.icmpv6;

public enum Icmpv6Type {
    DESTINATION_UNREACHABLE((byte) 0x01),
    PACKET_TOO_BIG((byte) 0x02),
    TIME_EXCEEDED((byte) 0x03),
    PARAMETER_PROBLEM((byte) 0x04),
    ECHO_REQUEST((byte) 0x80),
    ECHO_RESPONSE((byte) 0x81),
    MULTICAST_LISTENER_QUERY((byte) 0x82),
    MULTICAST_LISTENER_REPORT((byte) 0x83),
    MULTICAST_LISTENER_DONE((byte) 0x84),
    ROUTER_SOLICITATION((byte) 0x85),
    ROUTER_ADVERTISEMENT((byte) 0x86),
    NEIGHBOR_SOLICITATION((byte) 0x87),
    NEIGHBOR_ADVERTISEMENT((byte) 0x88),
    REDIRECT_MESSAGE((byte) 0x89),
    ROUTER_RENUMBERING((byte) 0x8A),
    ICMP_NODE_INFORMATION_QUERY((byte) 0x8B),
    ICMP_NODE_INFORMATION_RESPONSE((byte) 0x8C),
    INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION((byte) 0x8D),
    INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT((byte) 0x8E),
    MULTICAST_LISTENER_DISCOVERY((byte) 0x8F),
    HOME_AGENT_ADDRESS_DISCOVERY_REQUEST((byte) 0x90),
    HOME_AGENT_ADDRESS_DISCOVERY_REPLY((byte) 0x91),
    MOBILE_PREFIX_SOLICITATION((byte) 0x92),
    MOBILE_PREFIX_ADVERTISEMENT((byte) 0x93),
    CERTIFICATION_PATH_SOLICITATION((byte) 0x94),
    CERTIFICATION_PATH_ADVERTISEMENT((byte) 0x95),
    EXPERIMENTAL_MOBILE_PROTOCOLS((byte) 0x96),
    MULTICAST_ROUTER_ADVERTISEMENT((byte) 0x97),
    MULTICAST_ROUTER_SOLICITATION((byte) 0x98),
    MULTICAST_ROUTER_TERMINATION((byte) 0x99),
    FMIPV6_MESSAGES((byte) 0x9A),
    RPL((byte) 0x9B),
    ILNPV6_LOCATOR_UPDATE_MESSAGE((byte) 0x9C),
    DUPLICATE_ADDRESS_REQUEST((byte) 0x9D),
    DUPLICATE_ADDRESS_CONFIRMATION((byte) 0x9E),
    MPL_CONTROL_MESSAGE((byte) 0x9F),
    EXTENDED_ECHO_REQUEST((byte) 0xA0),
    EXTENDED_ECHO_REPLY((byte) 0xA1);

    private final byte type;

    Icmpv6Type(byte type) {
        this.type = type;
    }

    public byte getType() {
        return type;
    }

    public static Icmpv6Type getType(byte type) {
        for (Icmpv6Type identifier : Icmpv6Type.values()) {
            if (identifier.getType() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown ICMPv6 type " + type);
    }
}
