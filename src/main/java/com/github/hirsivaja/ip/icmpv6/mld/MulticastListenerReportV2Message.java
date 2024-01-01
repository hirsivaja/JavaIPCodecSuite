package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;

import java.nio.ByteBuffer;

public class MulticastListenerReportV2Message implements Icmpv6Message {
    private final MulticastAccessRecord[] multicastAccessRecords;

    public MulticastListenerReportV2Message(MulticastAccessRecord[] multicastAccessRecords) {
        this.multicastAccessRecords = multicastAccessRecords;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        out.putShort((short) multicastAccessRecords.length);
        for(MulticastAccessRecord multicastAccessRecord : multicastAccessRecords) {
            multicastAccessRecord.encode(out);
        }
    }

    @Override
    public int getLength() {
        int length = 4;
        for(MulticastAccessRecord multicastAccessRecord : multicastAccessRecords) {
            length += multicastAccessRecord.getLength();
        }
        return length;
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        in.getShort(); // RESERVED
        short numberOfGroupRecords = in.getShort();
        MulticastAccessRecord[] multicastAccessRecords = new MulticastAccessRecord[numberOfGroupRecords];
        for(int i = 0; i < multicastAccessRecords.length; i++) {
            multicastAccessRecords[i] = MulticastAccessRecord.decode(in);
        }
        return new MulticastListenerReportV2Message(multicastAccessRecords);
    }

    @Override
    public Icmpv6Type getType() {
        return Icmpv6Type.MULTICAST_LISTENER_REPORT_V2;
    }

    @Override
    public byte getCode() {
        return 0;
    }

    public MulticastAccessRecord[] getMulticastAccessRecords() {
        return multicastAccessRecords;
    }
}
