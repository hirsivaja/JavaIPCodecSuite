package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RplConsistencyCheck(
        RplSecurity security,
        byte rplInstance,
        byte flags,
        short ccNonce,
        byte[] dodagId,
        int destinationCounter,
        List<RplOption> options) implements RplPayload {
    private static final int MIN_LEN = 24;

    @Override
    public void encode(ByteBuffer out){
        security.encode(out);
        out.put(rplInstance);
        out.put(flags);
        out.putShort(ccNonce);
        out.put(dodagId);
        out.putInt(destinationCounter);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public RplPayloadType type() {
        return RplPayloadType.CONSISTENCY_CHECK;
    }

    @Override
    public int length() {
        return security.length() + MIN_LEN +
                options.stream().mapToInt(RplOption::length).sum();
    }

    public static RplConsistencyCheck decode(ByteBuffer in){
        RplSecurity security = RplSecurity.decode(in);
        byte rplInstance = in.get();
        byte flags = in.get();
        short ccNonce = in.getShort();
        byte[] dodagId = new byte[DODAG_ID_LEN];
        in.get(dodagId);
        int destinationCounter = in.getInt();
        List<RplOption> options = new ArrayList<>();
        while(in.hasRemaining()){
            options.add(RplOption.decode(in));
        }
        return new RplConsistencyCheck(security, rplInstance, flags, ccNonce, dodagId, destinationCounter, options);
    }
}
