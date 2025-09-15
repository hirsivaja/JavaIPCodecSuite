package com.github.hirsivaja.ip.icmp;

public sealed interface IcmpType permits IcmpType.GenericIcmpType, IcmpTypes {

    byte type();

    static IcmpType fromType(byte type) {
        for (IcmpType identifier : IcmpTypes.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        return new GenericIcmpType(type);
    }

    record GenericIcmpType(byte type) implements IcmpType {}
}
