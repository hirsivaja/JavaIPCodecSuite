package com.github.hirsivaja.ip.icmpv6;

public sealed interface Icmpv6Type permits Icmpv6Type.GenericIcmpv6Type, Icmpv6Types {
    byte type();

    static Icmpv6Type fromType(byte type) {
        for (Icmpv6Type identifier : Icmpv6Types.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        return new GenericIcmpv6Type(type);
    }

    record GenericIcmpv6Type(byte type) implements Icmpv6Type {}
}
