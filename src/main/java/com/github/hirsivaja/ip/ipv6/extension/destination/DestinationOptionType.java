package com.github.hirsivaja.ip.ipv6.extension.destination;

public enum DestinationOptionType {
    PAD_1((byte) 0x00, false, DestinationOption.SKIP), // 0x00
    PAD_N((byte) 0x01, false, DestinationOption.SKIP), // 0x01
    JUMBO_PAYLOAD((byte) 0x02, false, DestinationOption.DISCARD_AND_SEND_ERROR_IF_NOT_MULTICAST), // 0xC2
    RPL((byte) 0x03, true, DestinationOption.SKIP), // 0x23
    RPL_DISCARD((byte) 0x03, true, DestinationOption.DISCARD),  // 0x63 (DEPRECATED)
    TUNNEL_ENCAPSULATION_LIMIT((byte) 0x04, false, DestinationOption.SKIP), // 0x04
    ROUTER_ALERT((byte) 0x05, false, DestinationOption.SKIP), // 0x05
    QUICK_START((byte) 0x06, true, DestinationOption.SKIP), // 0x26
    CALIPSO((byte) 0x07, false, DestinationOption.SKIP), // 0x07
    SMF_DPD((byte) 0x08, false, DestinationOption.SKIP), // 0x08
    HOME_ADDRESS((byte) 0x09, false, DestinationOption.DISCARD_AND_SEND_ERROR_IF_NOT_MULTICAST), // 0xC9
    ENDPOINT_IDENTIFICATION((byte) 0x0A, false, DestinationOption.DISCARD_AND_SEND_ERROR),  // 0x8A (DEPRECATED)
    ILNP_NONCE((byte) 0x0B, false, DestinationOption.DISCARD_AND_SEND_ERROR), // 0x8B
    LINE_IDENTIFICATION((byte) 0x0C, false, DestinationOption.DISCARD_AND_SEND_ERROR), // 0x8C
    MPL_DEPRECATED((byte) 0x0D, false, DestinationOption.DISCARD), // 0x4D (DEPRECATED)
    MPL((byte) 0x0D, true, DestinationOption.DISCARD), // 0x6D
    IP_DFF((byte) 0x0E, true, DestinationOption.DISCARD_AND_SEND_ERROR_IF_NOT_MULTICAST), // 0xEE
    PDM((byte) 0x0F, false, DestinationOption.SKIP), // 0x0F
    MINIMUM_PATH_MTU((byte) 0x10, true, DestinationOption.SKIP), // 0x30
    IOAM((byte) 0x11, false, DestinationOption.SKIP), // 0x11
    IOAM_CHANGEABLE((byte) 0x11, true, DestinationOption.SKIP), // 0x31
    ALTMARK((byte) 0x12, false, DestinationOption.SKIP); // 0x12

    private final byte rest;
    private final boolean changeable;
    private final byte action;

    DestinationOptionType(byte rest, boolean changeable, byte action) {
        this.rest = rest;
        this.changeable = changeable;
        this.action = action;
    }

    public byte type() {
        byte type = (byte) (rest | (action << 6) & 0xFF);
        return changeable ? (byte) ((type | 0x20) & 0xFF) : type;
    }

    public static DestinationOptionType fromType(byte type) {
        for (DestinationOptionType identifier : DestinationOptionType.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown Destination / Hop By Hop Option type " + type);
    }
}
