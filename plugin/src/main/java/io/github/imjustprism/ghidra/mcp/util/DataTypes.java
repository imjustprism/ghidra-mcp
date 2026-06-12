package io.github.imjustprism.ghidra.mcp.util;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;

public final class DataTypes {

    private DataTypes() {}

    public static boolean isStringLike(Data data) {
        var typeName = data.getDataType().getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    public static DataType resolveDataType(DataTypeManager dtm, String name) {
        var hit = findDataType(dtm, name);
        if (hit != null) return hit;
        if (name.startsWith("P") && name.length() > 1) {
            var base = name.substring(1);
            if (base.equalsIgnoreCase("VOID")) return new PointerDataType(dtm.getDataType("/void"));
            var baseDt = findDataType(dtm, base);
            return new PointerDataType(baseDt != null ? baseDt : dtm.getDataType("/void"));
        }
        return switch (name.toLowerCase()) {
            case "int", "long" -> dtm.getDataType("/int");
            case "uint", "unsigned int", "unsigned long", "dword" -> dtm.getDataType("/uint");
            case "short" -> dtm.getDataType("/short");
            case "ushort", "unsigned short", "word" -> dtm.getDataType("/ushort");
            case "char", "byte" -> dtm.getDataType("/char");
            case "uchar", "unsigned char" -> dtm.getDataType("/uchar");
            case "longlong", "__int64" -> dtm.getDataType("/longlong");
            case "ulonglong", "unsigned __int64" -> dtm.getDataType("/ulonglong");
            case "bool", "boolean" -> dtm.getDataType("/bool");
            case "void" -> dtm.getDataType("/void");
            default -> {
                var direct = dtm.getDataType("/" + name);
                yield direct != null ? direct : dtm.getDataType("/int");
            }
        };
    }

    public static DataType findDataType(DataTypeManager dtm, String name) {
        for (var it = dtm.getAllDataTypes(); it.hasNext(); ) {
            var dt = it.next();
            if (dt.getName().equals(name) || dt.getName().equalsIgnoreCase(name)) return dt;
        }
        return null;
    }
}
