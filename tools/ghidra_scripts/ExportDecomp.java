// Headless: decompile every function and write C + basic metadata to a file (read-only analysis).
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class ExportDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "decomp.c";
        // seed the known entry point for raw blobs
        if (args.length > 1) {
            for (String a : args[1].split(",")) {
                Address ep = toAddr(Long.decode(a));
                if (getFunctionAt(ep) == null) { disassemble(ep); createFunction(ep, null); }
            }
            analyzeAll(currentProgram);
        }
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
            int n = 0;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                DecompileResults r = d.decompileFunction(f, 60, monitor);
                w.println("// ==== " + f.getName() + " @ " + f.getEntryPoint() + " size " + f.getBody().getNumAddresses());
                w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed: " + r.getErrorMessage());
                n++;
            }
            println("exported " + n + " functions to " + out);
        }
    }
}
