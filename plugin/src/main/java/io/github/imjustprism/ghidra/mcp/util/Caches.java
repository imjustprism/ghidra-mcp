package io.github.imjustprism.ghidra.mcp.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Caches {

    private Caches() {}

    public static <K, V> Map<K, V> lru(int capacity) {
        return Collections.synchronizedMap(new LinkedHashMap<>(capacity, 0.75f, true) {
            @Override protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > capacity;
            }
        });
    }
}
