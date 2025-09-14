package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RouterRenumberingCommand(List<PrefixControlOperation> prefixControlOperations) implements RouterRenumberingBody {

    @Override
    public void encode(ByteBuffer out) {
        prefixControlOperations.forEach(prefixControlOperation -> prefixControlOperation.encode(out));
    }

    @Override
    public int length() {
        return prefixControlOperations.stream().mapToInt(PrefixControlOperation::length).sum();
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.ROUTER_RENUMBERING_COMMAND;
    }

    public static RouterRenumberingCommand decode(ByteBuffer in) {
        List<PrefixControlOperation> prefixControlOperations = new ArrayList<>();
        while(in.hasRemaining()) {
            prefixControlOperations.add(PrefixControlOperation.decode(in));
        }
        return new RouterRenumberingCommand(prefixControlOperations);
    }
}
