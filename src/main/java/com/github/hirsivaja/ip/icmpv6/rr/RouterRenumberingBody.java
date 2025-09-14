package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import java.nio.ByteBuffer;

public sealed interface RouterRenumberingBody permits RouterRenumberingCommand, RouterRenumberingResult, SequenceNumberReset {
    void encode(ByteBuffer out);
    int length();
    Icmpv6Code code();

    public static RouterRenumberingBody decode(ByteBuffer in, Icmpv6Code code) {
        return switch(code) {
            case Icmpv6Codes.ROUTER_RENUMBERING_COMMAND -> RouterRenumberingCommand.decode(in);
            case Icmpv6Codes.ROUTER_RENUMBERING_RESULT -> RouterRenumberingResult.decode(in);
            case Icmpv6Codes.SEQUENCE_NUMBER_RESET -> new SequenceNumberReset();
            default -> throw new IllegalArgumentException();
        };
    }
}
