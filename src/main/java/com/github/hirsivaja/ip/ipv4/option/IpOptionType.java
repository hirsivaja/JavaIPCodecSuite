package com.github.hirsivaja.ip.ipv4.option;

public enum IpOptionType {
    END_OF_OPTIONS_LIST((byte) 0x00, IpOption.CONTROL, false),
    NO_OPERATION((byte) 0x01, IpOption.CONTROL, false),
    SECURITY((byte) 0x02, IpOption.CONTROL, true),
    LOOSE_SOURCE_ROUTE((byte) 0x03, IpOption.CONTROL, true),
    TIME_STAMP((byte) 0x04, IpOption.DEBUG, false),
    EXTENDED_SECURITY((byte) 0x05, IpOption.CONTROL, true),
    COMMERCIAL_SECURITY((byte) 0x06, IpOption.CONTROL, true),
    RECORD_ROUTE((byte) 0x07, IpOption.CONTROL, false),
    STREAM_ID((byte) 0x08, IpOption.CONTROL, true),
    STRICT_SOURCE_ROUTE((byte) 0x09, IpOption.CONTROL, true),
    EXPERIMENTAL_MEASUREMENT((byte) 0x0A, IpOption.CONTROL, false),
    MTU_PROBE((byte) 0x0B, IpOption.CONTROL, false),
    MTU_REPLY((byte) 0x0C, IpOption.CONTROL, false),
    EXPERIMENTAL_FLOW_CONTROL((byte) 0x0D, IpOption.DEBUG, true),
    EXPERIMENTAL_ACCESS_CONTROL((byte) 0x0E, IpOption.CONTROL, true),
    ENCODE((byte) 0x0F, IpOption.CONTROL, false),
    IMI_TRAFFIC_DESCRIPTOR((byte) 0x10, IpOption.CONTROL, true),
    EXTENDED_INTERNET_PROTOCOL((byte) 0x11, IpOption.CONTROL, true),
    TRACEROUTE((byte) 0x12, IpOption.DEBUG, false),
    ADDRESS_EXTENSION((byte) 0x13, IpOption.CONTROL, true),
    ROUTER_ALERT((byte) 0x14, IpOption.CONTROL, true),
    SELECTIVE_DIRECTED_BROADCAST((byte) 0x15, IpOption.CONTROL, true),
    // 0x16 is unassigned
    DYNAMIC_PACKET_STATE((byte) 0x17, IpOption.CONTROL, true),
    UPSTREAM_MULTICAST_PACKET((byte) 0x18, IpOption.CONTROL, true),
    QUICK_START((byte) 0x19, IpOption.CONTROL, false),
    EXPERIMENT_1((byte) 0x1E, IpOption.CONTROL, false),
    EXPERIMENT_2((byte) 0x1E, IpOption.DEBUG, false),
    EXPERIMENT_3((byte) 0x1E, IpOption.CONTROL, true),
    EXPERIMENT_4((byte) 0x1E, IpOption.DEBUG, true);

    private final byte number;
    private final byte optionClass;
    private final boolean copy;

    IpOptionType(byte number, byte optionClass, boolean copy) {
        this.number = number;
        this.optionClass = optionClass;
        this.copy = copy;
    }

    public byte type() {
        byte type = (byte) (number | (optionClass << 5) & 0xFF);
        return copy ? (byte) ((type | 0x80) & 0xFF) : type;
    }

    public static IpOptionType fromType(byte type) {
        for (IpOptionType identifier : IpOptionType.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown IP Option type " + type);
    }
}
