package com.github.hirsivaja.ip;

public sealed interface IpProtocol permits IpProtocol.GenericIpProtocol, IpProtocol.Type {
    byte type();

    public static IpProtocol fromType(byte type) {
        for (Type identifier : Type.values()) {
            if (identifier.type() == type) {
                return identifier;
            }
        }
        return new GenericIpProtocol(type);
    }

    public record GenericIpProtocol(byte type) implements IpProtocol {}

    public enum Type implements IpProtocol {
        HOP_BY_HOP((byte) 0x00),
        ICMP((byte) 0x01),
        IGMP((byte) 0x02),
        TCP((byte) 0x06),
        UDP((byte) 0x11),
        ENCAPSULATION((byte) 0x29),
        ROUTING((byte) 0x2B),
        FRAGMENTATION((byte) 0x2C),
        ESP((byte) 0x32),
        AUTHENTICATION((byte) 0x33),
        ICMPV6((byte) 0x3A),
        NO_NEXT((byte) 0x3B),
        DESTINATION((byte) 0x3C);

        private final byte type;

        Type(byte type) {
            this.type = type;
        }

        @Override
        public byte type() {
            return type;
        }
    }
}
