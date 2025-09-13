package com.github.hirsivaja.ip.icmp;

public sealed interface IcmpCode permits IcmpCode.GenericIcmpCode, IcmpCodes {
    
    IcmpType type();

    byte code();

    public static IcmpCode fromType(IcmpType type, byte code) {
        for (IcmpCode identifier : IcmpCodes.values()) {
            if (identifier.type() == type && identifier.code() == code) {
                return identifier;
            }
        }
        return new GenericIcmpCode(type, code);
    }

    record GenericIcmpCode(IcmpType type, byte code) implements IcmpCode {}
}
