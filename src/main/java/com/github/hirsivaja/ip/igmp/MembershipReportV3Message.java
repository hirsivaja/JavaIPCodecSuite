package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record MembershipReportV3Message(
        IgmpType type,
        byte code,
        List<GroupRecord> groupRecords) implements IgmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        out.putShort((short) groupRecords.size());
        for(GroupRecord groupRecord : groupRecords) {
            groupRecord.encode(out);
        }
    }

    @Override
    public int length() {
        int length = 4;
        for(GroupRecord groupRecord : groupRecords) {
            length += groupRecord.length();
        }
        return length;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        in.getShort(); // RESERVED
        short numberOfGroupRecords = in.getShort();
        List<GroupRecord> groupRecords = new ArrayList<>();
        for(int i = 0; i < numberOfGroupRecords; i++) {
            groupRecords.add(GroupRecord.decode(in));
        }
        return new MembershipReportV3Message(type, code, groupRecords);
    }
}
