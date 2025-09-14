package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RouterRenumberingResult(List<MatchReport> matchReports) implements RouterRenumberingBody {

    @Override
    public void encode(ByteBuffer out) {
        matchReports.forEach(matchReport -> matchReport.encode(out));
    }

    @Override
    public int length() {
        return matchReports.stream().mapToInt(MatchReport::length).sum();
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.ROUTER_RENUMBERING_RESULT;
    }
    
    public static RouterRenumberingResult decode(ByteBuffer in) {
        List<MatchReport> matchReports = new ArrayList<>();
        while(in.hasRemaining()) {
            matchReports.add(MatchReport.decode(in));
        }
        return new RouterRenumberingResult(matchReports);
    }
}
