package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record MulticastListenerReportV2Message(
        List<MulticastAccessRecord> multicastAccessRecords) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        out.putShort((short) multicastAccessRecords.size());
        for(MulticastAccessRecord multicastAccessRecord : multicastAccessRecords) {
            multicastAccessRecord.encode(out);
        }
    }

    @Override
    public int length() {
        int length = BASE_LEN + 4;
        for(MulticastAccessRecord multicastAccessRecord : multicastAccessRecords) {
            length += multicastAccessRecord.getLength();
        }
        return length;
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        in.getShort(); // RESERVED
        short numberOfGroupRecords = in.getShort();
        List<MulticastAccessRecord> multicastAccessRecords = new ArrayList<>();
        for(int i = 0; i < numberOfGroupRecords; i++) {
            multicastAccessRecords.add(MulticastAccessRecord.decode(in));
        }
        return new MulticastListenerReportV2Message(multicastAccessRecords);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Type.MULTICAST_LISTENER_REPORT_V2;
    }

    @Override
    public byte code() {
        return 0;
    }
}
