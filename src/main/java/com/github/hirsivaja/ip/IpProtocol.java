package com.github.hirsivaja.ip;

public sealed interface IpProtocol permits IpProtocol.GenericIpProtocol, IpProtocols {
    byte type();

    static IpProtocol fromType(byte type) {
        for (IpProtocol identifier : IpProtocols.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        return new GenericIpProtocol(type);
    }

    record GenericIpProtocol(byte type) implements IpProtocol {}
}
