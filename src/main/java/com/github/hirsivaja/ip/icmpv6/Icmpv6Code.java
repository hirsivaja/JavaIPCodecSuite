package com.github.hirsivaja.ip.icmpv6;

public sealed interface Icmpv6Code permits Icmpv6Code.GenericIcmpv6Code, Icmpv6Codes {
    Icmpv6Type type();
    byte code();

    static Icmpv6Code fromType(Icmpv6Type type, byte code) {
        for (Icmpv6Code identifier : Icmpv6Codes.values()) {
            if (identifier.type() == type && identifier.code() == code) {
                return identifier;
            }
        }
        return new GenericIcmpv6Code(type, code);
    }

    record GenericIcmpv6Code(Icmpv6Type type, byte code) implements Icmpv6Code {}
}
