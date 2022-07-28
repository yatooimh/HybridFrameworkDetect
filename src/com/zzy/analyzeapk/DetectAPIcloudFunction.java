package com.zzy.analyzeapk;

import org.json.JSONObject;
import soot.*;
import soot.util.Chain;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class DetectAPIcloudFunction {
    public static void findAPIcloudFunctions(Chain<SootClass> cs, JSONObject obj) {
        for(SootClass c : cs) {
            List<SootMethod> ms = c.getMethods();
            //Chain<SootField> fs = c.getFields();
            for (SootMethod m : ms) {
                Set<String> addWhiteListEntry = new HashSet<>();
                Set<String> judgeisUrlWhiteListed = new HashSet<>();
                if (m.hasActiveBody()) {
                    Body b = m.getActiveBody();
                    final PatchingChain<Unit> units = b.getUnits();
                    for (Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext(); ) {
                        final Unit u = iter.next();
                        if (u.toString().contains("Failed to add origin")) addWhiteListEntry.add("domain-config");

                        if (u.toString().contains("getScheme")) judgeisUrlWhiteListed.add("getScheme");
                        if (u.toString().contains("file")) judgeisUrlWhiteListed.add("file");
                        if (u.toString().contains("content")) judgeisUrlWhiteListed.add("content");
                        if (u.toString().contains("hasNext")) judgeisUrlWhiteListed.add("hasNext");
                    }
                }
                if (addWhiteListEntry.size() == 1) {
                    JSONObject subobj = new JSONObject();
                    subobj.put("name", "addWhiteListEntry");
                    subobj.put("location", c.getName());
                    subobj.put("signature", m.getSignature());
                    obj.accumulate("Whitelist method", subobj);
                }
                if (judgeisUrlWhiteListed.size() == 4) {
                    JSONObject subobj = new JSONObject();
                    subobj.put("name", "isUrlWhiteListed");
                    subobj.put("location", c.getName());
                    subobj.put("signature", m.getSignature());
                    obj.accumulate("Whitelist method", subobj);
                }
            }
        }
    }
}
