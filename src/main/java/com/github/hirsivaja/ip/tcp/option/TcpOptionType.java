package com.github.hirsivaja.ip.tcp.option;

public enum TcpOptionType {
    END_OF_OPTIONS_LIST((byte) 0x00),
    NO_OPERATION((byte) 0x01),
    MAXIMUM_SEGMENT_SIZE((byte) 0x02),
    WINDOW_SCALE((byte) 0x03),
    SACK_PERMITTED((byte) 0x04),
    SACK((byte) 0x05),
    ECHO((byte) 0x06), // OBSOLETE
    ECHO_REPLY((byte) 0x07), // OBSOLETE
    TIMESTAMPS((byte) 0x08),
    PARTIAL_ORDER_CONNECTION_PERMITTED((byte) 0x09), // OBSOLETE
    PARTIAL_ORDER_SERVICE_PROFILE((byte) 0x0A), // OBSOLETE
    CC((byte) 0x0B), // OBSOLETE
    CC_NEW((byte) 0x0C), // OBSOLETE
    CC_ECHO((byte) 0x0D), // OBSOLETE
    TCP_ALTERNATE_CHECKSUM_REQUEST((byte) 0x0E), // OBSOLETE
    TCP_ALTERNATE_CHECKSUM_DATA((byte) 0x0F), // OBSOLETE
    SKEETER((byte) 0x10),
    BUBBA((byte) 0x11),
    TRAILER_CHECKSUM((byte) 0x12),
    MD5_SIGNATURE((byte) 0x13), // OBSOLETE
    SCPS_CAPABILITIES((byte) 0x14),
    SELECTIVE_NEGATIVE_ACKNOWLEDGEMENTS((byte) 0x15),
    RECORD_BOUNDARIES((byte) 0x16),
    CORRUPTION_EXPERIENCED((byte) 0x17),
    SNAP((byte) 0x18),
    UNASSIGNED((byte) 0x19),
    TCP_COMPRESSION_FILTER((byte) 0x1A),
    QUICK_START_RESPONSE((byte) 0x1B),
    USER_TIMEOUT((byte) 0x1C),
    TCP_AUTHENTICATION((byte) 0x1D),
    MULTIPATH_TCP((byte) 0x1E),
    UNAUTHORIZED_1((byte) 0x1F),
    UNAUTHORIZED_2((byte) 0x20),
    UNAUTHORIZED_3((byte) 0x21),
    TCP_FAST_OPEN_COOKIE((byte) 0x22),
    // 0x23-0x44 RESERVED
    ENCRYPTION_NEGOTIATION((byte) 0x45),
    UNAUTHORIZED_4((byte) 0x46),
    // 0x47-0x4B RESERVED
    UNAUTHORIZED_5((byte) 0x4C),
    UNAUTHORIZED_6((byte) 0x4D),
    UNAUTHORIZED_7((byte) 0x4E),
    // 0x4F-0xAB RESERVED
    ACCURATE_ECN_ORDER_0((byte) 0xAC),
    // 0xAD RESERVED
    ACCURATE_ECN_ORDER_1((byte) 0xAE),
    // 0xAF-0xFC RESERVED
    EXPERIMENTAL_1((byte) 0xFD),
    EXPERIMENTAL_2((byte) 0xFE);

    private final byte type;

    TcpOptionType(byte type) {
        this.type = type;
    }

    public byte type() {
        return type;
    }

    public static TcpOptionType fromType(byte type) {
        for (TcpOptionType identifier : TcpOptionType.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown TCP Option type " + type);
    }
}
