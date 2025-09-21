package com.github.hirsivaja.ip.icmpv6;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record Ilnpv6LocatorUpdateMessage(byte operation, List<Long> locators, List<Short> preferences, List<Short> lifetimes) implements Icmpv6Message {

    public Ilnpv6LocatorUpdateMessage {
        if(locators.size() != preferences.size() || locators.size() != lifetimes.size()) {
            throw new IllegalArgumentException("There should be an equal amount of 'locators', 'preferences' and 'lifetimes'.");
        }
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put((byte) locators.size());
        out.put(operation);
        out.putShort((short) 0); // RESERVED
        for(int i = 0; i < locators.size(); i++) {
            out.putLong(locators.get(i));
            out.putShort(preferences.get(i));
            out.putShort(lifetimes.get(i));
        }
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + locators.size() * 12;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        byte numberOfLocs = in.get();
        byte operation = in.get();
        in.getShort(); // RESERVED
        List<Long> locators = new ArrayList<>();
        List<Short> preferences = new ArrayList<>();
        List<Short> lifetimes = new ArrayList<>();
        for(int i = 0; i < numberOfLocs; i++) {
            locators.add(in.getLong());
            preferences.add(in.getShort());
            lifetimes.add(in.getShort());
        }
        return new Ilnpv6LocatorUpdateMessage(operation, locators, preferences, lifetimes);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.ILNPV6_LOCATOR_UPDATE_MESSAGE;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.ILNPV6_LOCATOR_UPDATE_MESSAGE;
    }
}
