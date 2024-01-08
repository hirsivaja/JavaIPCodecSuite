package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;

public class MembershipReportV3Message implements IgmpMessage {
    private final IgmpType type;
    private final byte code;
    private final GroupRecord[] groupRecords;

    public MembershipReportV3Message(IgmpType type, byte code, GroupRecord[] groupRecords) {
        this.type = type;
        this.code = code;
        this.groupRecords = groupRecords;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        out.putShort((short) groupRecords.length);
        for(GroupRecord groupRecord : groupRecords) {
            groupRecord.encode(out);
        }
    }

    @Override
    public int getLength() {
        int length = BASE_LEN + 4;
        for(GroupRecord groupRecord : groupRecords) {
            length += groupRecord.getLength();
        }
        return length;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        in.getShort(); // RESERVED
        short numberOfGroupRecords = in.getShort();
        GroupRecord[] groupRecords = new GroupRecord[numberOfGroupRecords];
        for(int i = 0; i < groupRecords.length; i++) {
            groupRecords[i] = GroupRecord.decode(in);
        }
        return new MembershipReportV3Message(type, code, groupRecords);
    }

    @Override
    public IgmpType getType() {
        return type;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public GroupRecord[] getGroupRecords() {
        return groupRecords;
    }
}
