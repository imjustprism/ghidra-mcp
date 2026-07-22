import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;

public class Probe extends GhidraScript {
    @Override
    public void run() throws Exception {
        PluginTool tool = state.getTool();
        println("PROBE TOOL=" + tool);
        if (tool != null) {
            println("PROBE TOOL_CLASS=" + tool.getClass().getName());
            try {
                Object pm = tool.getService(ProgramManager.class);
                println("PROBE PROGRAM_MANAGER=" + pm);
            } catch (Throwable t) {
                println("PROBE PM_ERROR=" + t);
            }
        }
        println("PROBE CURRENT_PROGRAM=" + (currentProgram == null ? "null" : currentProgram.getName()));
        println("PROBE DONE");
    }
}
