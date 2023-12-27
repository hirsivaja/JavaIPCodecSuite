package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class RplConsistencyCheck implements RplPayload {
    private static final int MIN_LEN = 24;
    private final RplSecurity security;
    private final byte rplInstance;
    private final byte flags;
    private final short ccNonce;
    private final byte[] dodagId;
    private final int destinationCounter;
    private final List<RplOption> options;

    public RplConsistencyCheck(RplSecurity security, byte rplInstance, byte flags, short ccNonce,
                               byte[] dodagId, int destinationCounter, List<RplOption> options) {
        this.security = security;
        this.rplInstance = rplInstance;
        this.flags = flags;
        this.ccNonce = ccNonce;
        this.dodagId = dodagId;
        this.destinationCounter = destinationCounter;
        this.options = options;
    }

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
    public RplPayloadType getType() {
        return RplPayloadType.CONSISTENCY_CHECK;
    }

    @Override
    public int getLength() {
        return security.getLength() + MIN_LEN +
                options.stream().mapToInt(RplOption::getLength).sum();
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

    @Override
    public RplSecurity getSecurity() {
        return security;
    }

    public byte getRplInstance() {
        return rplInstance;
    }

    public byte getFlags() {
        return flags;
    }

    public short getCcNonce() {
        return ccNonce;
    }

    public byte[] getDodagId() {
        return dodagId;
    }

    public int getDestinationCounter() {
        return destinationCounter;
    }

    @Override
    public List<RplOption> getOptions() {
        return options;
    }
}
