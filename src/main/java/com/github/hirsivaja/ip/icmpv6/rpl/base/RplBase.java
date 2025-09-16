package com.github.hirsivaja.ip.icmpv6.rpl.base;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;

import java.nio.ByteBuffer;

public interface RplBase {
    void encode(ByteBuffer out);
    Icmpv6Code code(boolean secured);
    int length();
    boolean hasDodagid();

    static RplBase decode(ByteBuffer in, Icmpv6Code code) {
        return switch (code) {
            case Icmpv6Codes.DIS,
                 Icmpv6Codes.SECURE_DIS -> RplDis.decode(in);
            case Icmpv6Codes.DIO,
                 Icmpv6Codes.SECURE_DIO -> RplDio.decode(in);
            case Icmpv6Codes.DAO,
                 Icmpv6Codes.SECURE_DAO -> RplDao.decode(in);
            case Icmpv6Codes.DAO_ACK,
                 Icmpv6Codes.SECURE_DAO_ACK -> RplDaoAck.decode(in);
            case Icmpv6Codes.CONSISTENCY_CHECK -> RplConsistencyCheck.decode(in);
            default -> throw new IllegalArgumentException("Unexpected value: " + code);
        };
    }
}
