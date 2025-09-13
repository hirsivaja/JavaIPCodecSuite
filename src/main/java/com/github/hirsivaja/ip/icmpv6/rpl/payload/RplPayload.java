package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.List;

public interface RplPayload {
    int DODAG_ID_LEN = 16;

    void encode(ByteBuffer out);

    Icmpv6Code code();

    int length();

    default boolean hasSecurity() {
        return security() != null;
    }

    RplSecurity security();

    List<RplOption> options();

    default byte[] toByteArray(){
        ByteBuffer out = ByteBuffer.allocate(length());
        encode(out);
        byte[] outBytes = new byte[out.rewind().remaining()];
        out.get(outBytes);
        return outBytes;
    }

    static RplPayload fromByteArray(byte[] rplPayload, Icmpv6Code code){
        return decode(ByteBuffer.wrap(rplPayload), code);
    }

    static RplPayload decode(ByteBuffer in, Icmpv6Code code) {
        return switch (code) {
            case Icmpv6Codes.DIS -> RplDis.decode(in, false);
            case Icmpv6Codes.DIO -> RplDio.decode(in, false);
            case Icmpv6Codes.DAO -> RplDao.decode(in, false);
            case Icmpv6Codes.DAO_ACK -> RplDaoAck.decode(in, false);
            case Icmpv6Codes.SECURE_DIS -> RplDis.decode(in, true);
            case Icmpv6Codes.SECURE_DIO -> RplDio.decode(in, true);
            case Icmpv6Codes.SECURE_DAO -> RplDao.decode(in, true);
            case Icmpv6Codes.SECURE_DAO_ACK -> RplDaoAck.decode(in, true);
            case Icmpv6Codes.CONSISTENCY_CHECK -> RplConsistencyCheck.decode(in);
            default -> throw new IllegalArgumentException("Unexpected value: " + code);
        };
    }
}
