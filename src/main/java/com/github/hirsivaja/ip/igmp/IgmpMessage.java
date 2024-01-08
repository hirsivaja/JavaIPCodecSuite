package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;

public interface IgmpMessage {
    int BASE_LEN = 4;

    IgmpType getType();
    byte getCode();
    void encode(ByteBuffer out);
    int getLength();

    static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        switch (type) {
            case CREATE_GROUP_REQUEST:
            case CREATE_GROUP_REPLY:
            case JOIN_GROUP_REQUEST:
            case JOIN_GROUP_REPLY:
            case LEAVE_GROUP_REQUEST:
            case LEAVE_GROUP_REPLY:
            case CONFIRM_GROUP_REQUEST:
            case CONFIRM_GROUP_REPLY:
                return GenericIgmpV0Message.decode(in, type, code);
            case MEMBERSHIP_QUERY: return MembershipQueryMessage.decode(in, type, code);
            case MEMBERSHIP_REPORT_V1: return GenericIgmpV1Message.decode(in, type, code);
            case MEMBERSHIP_REPORT_V2:
            case LEAVE_GROUP_V2:
                return GenericIgmpV2Message.decode(in, type, code);
            case MEMBERSHIP_REPORT_V3: return MembershipReportV3Message.decode(in, type, code);
            default: throw new IllegalArgumentException("Unknown IGMP message " + type);
        }
    }
}
