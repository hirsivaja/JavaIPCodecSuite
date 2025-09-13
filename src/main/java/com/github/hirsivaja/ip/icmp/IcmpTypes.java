package com.github.hirsivaja.ip.icmp;

public enum IcmpTypes implements IcmpType {
    ECHO_REPLY((byte) 0x00),
    DESTINATION_UNREACHABLE((byte) 0x03),
    SOURCE_QUENCH((byte) 0x04),
    REDIRECT_MESSAGE((byte) 0x05),
    ALTERNATE_HOST_ADDRESS((byte) 0x06),
    ECHO_REQUEST((byte) 0x08),
    ROUTER_ADVERTISEMENT((byte) 0x09),
    ROUTER_SOLICITATION((byte) 0x0A),
    TIME_EXCEEDED((byte) 0x0B),
    PARAMETER_PROBLEM((byte) 0x0C),
    TIMESTAMP((byte) 0x0D),
    TIMESTAMP_REPLY((byte) 0x0E),
    INFORMATION_REQUEST((byte) 0x0F),
    INFORMATION_REPLY((byte) 0x10),
    ADDRESS_MASK_REQUEST((byte) 0x11),
    ADDRESS_MASK_REPLY((byte) 0x12),
    TRACEROUTE((byte) 0x1E),
    DATAGRAM_CONVERSION_ERROR((byte) 0x1F),
    MOBILE_HOST_REDIRECT((byte) 0x20),
    WHERE_ARE_YOU((byte) 0x21),
    HERE_I_AM((byte) 0x22),
    MOBILE_REGISTRATION_REQUEST((byte) 0x23),
    MOBILE_REGISTRATION_REPLY((byte) 0x24),
    DOMAIN_NAME_REQUEST((byte) 0x25),
    DOMAIN_NAME_REPLY((byte) 0x26),
    SKIP_ALGORITHM_DISCOVERY_PROTOCOL((byte) 0x27),
    PHOTURIS((byte) 0x28),
    EXPERIMENTAL_MOBILE_PROTOCOLS((byte) 0x29),
    EXTENDED_ECHO_REQUEST((byte) 0x2A),
    EXTENDED_ECHO_REPLY((byte) 0x2B);

    private final byte type;

    IcmpTypes(byte type) {
        this.type = type;
    }

    @Override
    public byte type() {
        return type;
    }
}
