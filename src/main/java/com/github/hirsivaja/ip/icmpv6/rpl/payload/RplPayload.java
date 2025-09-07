package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.List;

public interface RplPayload {
    int DODAG_ID_LEN = 16;

    void encode(ByteBuffer out);

    RplPayloadType type();

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

    static RplPayload fromByteArray(byte[] rplPayload, RplPayloadType code){
        return decode(ByteBuffer.wrap(rplPayload), code);
    }

    static RplPayload decode(ByteBuffer in, RplPayloadType code) {
        return switch (code) {
            case DIS -> RplDis.decode(in, false);
            case DIO -> RplDio.decode(in, false);
            case DAO -> RplDao.decode(in, false);
            case DAO_ACK -> RplDaoAck.decode(in, false);
            case SECURE_DIS -> RplDis.decode(in, true);
            case SECURE_DIO -> RplDio.decode(in, true);
            case SECURE_DAO -> RplDao.decode(in, true);
            case SECURE_DAO_ACK -> RplDaoAck.decode(in, true);
            case CONSISTENCY_CHECK -> RplConsistencyCheck.decode(in);
            default -> throw new IllegalArgumentException("Unexpected value: " + code);
        };
    }
}
