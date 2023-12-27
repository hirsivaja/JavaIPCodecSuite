package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.List;

public interface RplPayload {
    int DODAG_ID_LEN = 16;

    void encode(ByteBuffer out);

    RplPayloadType getType();

    int getLength();

    default boolean hasSecurity() {
        return getSecurity() != null;
    }

    RplSecurity getSecurity();

    List<RplOption> getOptions();

    default byte[] toByteArray(){
        ByteBuffer out = ByteBuffer.allocate(getLength());
        encode(out);
        byte[] outBytes = new byte[out.rewind().remaining()];
        out.get(outBytes);
        return outBytes;
    }

    static RplPayload fromByteArray(byte[] rplPayload, RplPayloadType code){
        return decode(ByteBuffer.wrap(rplPayload), code);
    }

    static RplPayload decode(ByteBuffer in, RplPayloadType code) {
        switch (code) {
            case DIS: return RplDis.decode(in, false);
            case DIO: return RplDio.decode(in, false);
            case DAO: return RplDao.decode(in, false);
            case DAO_ACK: return RplDaoAck.decode(in, false);
            case SECURE_DIS: return RplDis.decode(in, true);
            case SECURE_DIO: return RplDio.decode(in, true);
            case SECURE_DAO: return RplDao.decode(in, true);
            case SECURE_DAO_ACK: return RplDaoAck.decode(in, true);
            case CONSISTENCY_CHECK: return RplConsistencyCheck.decode(in);
            default: throw new IllegalArgumentException("Unexpected value: " + code);
        }
    }
}
