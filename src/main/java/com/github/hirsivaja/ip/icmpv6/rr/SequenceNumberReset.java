package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import java.nio.ByteBuffer;

public record SequenceNumberReset() implements RouterRenumberingBody {

    @Override
    public void encode(ByteBuffer out) {
        // DOES NOT CONTAIN ANYTHING
    }

    @Override
    public int length() {
        return 0;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.SEQUENCE_NUMBER_RESET;
    }
}
