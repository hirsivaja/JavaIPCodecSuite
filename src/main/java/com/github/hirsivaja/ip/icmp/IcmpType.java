package com.github.hirsivaja.ip.icmp;

public sealed interface IcmpType permits IcmpType.GenericIcmpType, IcmpTypes {

    byte type();

    public static IcmpType fromType(byte type) {
        for (IcmpType identifier : IcmpTypes.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown ICMP type " + type);
    }

    record GenericIcmpType(byte type) implements IcmpType {}
}
