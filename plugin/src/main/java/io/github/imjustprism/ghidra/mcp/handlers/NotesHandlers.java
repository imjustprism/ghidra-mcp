package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public final class NotesHandlers {

    private static final String OPTIONS_NODE = "MCP Notes";
    private static final String DEFAULT_CATEGORY = "MCP";

    private final PluginContext ctx;
    private final AtomicLong seq = new AtomicLong();

    public NotesHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.postForm("/analysis_note",
                p -> addNote(p.get("text"), p.get("address"), p.get("category")));
        routes.getQuery("/analysis_notes", this::listNotes);
    }

    private String addNote(String text, String address, String category) {
        if (text == null || text.isBlank()) throw new IllegalArgumentException("text is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var cat = category == null || category.isBlank() ? DEFAULT_CATEGORY : category.trim();
        if (address != null && !address.isBlank()) {
            var a = program.getAddressFactory().getAddress(address.trim());
            if (a == null) throw new IllegalArgumentException("invalid address: " + address);
            ctx.runOnSwingTx(program, "analysis_note", () -> {
                program.getBookmarkManager().setBookmark(a, BookmarkType.NOTE, cat, text);
                return true;
            });
            return "noted at " + Responses.addr(a) + " [" + cat + "] (persists with the program; save to keep)";
        }
        var key = "note_" + seq.incrementAndGet();
        ctx.runOnSwingTx(program, "analysis_note", () -> {
            program.getOptions(OPTIONS_NODE).setString(key, text);
            return true;
        });
        return "noted (program-level) key=" + key + " (persists with the program; save to keep)";
    }

    private String listNotes(Map<String, String> q) {
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var t = Responses.table(q, new String[]{"scope", "category", "note"}, 32);
        Options opts = program.getOptions(OPTIONS_NODE);
        for (var name : opts.getOptionNames()) {
            t.row(name, DEFAULT_CATEGORY, opts.getString(name, ""));
        }
        addBookmarkNotes(program, t);
        return t.build();
    }

    private void addBookmarkNotes(Program program, Responses.Table t) {
        var it = program.getBookmarkManager().getBookmarksIterator(BookmarkType.NOTE);
        while (it.hasNext()) {
            Bookmark b = it.next();
            t.row(Responses.addr(b.getAddress()), b.getCategory(), b.getComment());
        }
    }
}
