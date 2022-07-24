package com.zzy.analyzeapk;

import org.json.JSONObject;
import soot.*;
import soot.util.Chain;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class DetectCordovaFunction {
    public static void findCordovaFunctions(Chain<SootClass> cs, JSONObject obj) throws IOException {
        for(SootClass c : cs) {
            List<SootMethod> ms = c.getMethods();
            //Chain<SootField> fs = c.getFields();
            for (SootMethod m : ms) {
                Set<String> judgeXmlParse = new HashSet<>(), judgeaddWhiteListEntry = new HashSet<>(), judgeisUrlWhiteListed = new HashSet<>();
                if (m.hasActiveBody()) {
                    Body b = m.getActiveBody();
                    final PatchingChain<Unit> units = b.getUnits();
                    for (Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext(); ) {
                        final Unit u = iter.next();
                        if (u.toString().contains("http://*/*")) judgeXmlParse.add("http://*/*");
                        if (u.toString().contains("https://*/*")) judgeXmlParse.add("https://*/*");
                        if (u.toString().contains("data:*")) judgeXmlParse.add("data:*");
                        if (u.toString().contains("allow-intent")) judgeXmlParse.add("allow-intent");
                        if (u.toString().contains("Failed to add origin"))
                            judgeaddWhiteListEntry.add("Failed to add origin");
                        if (u.toString().contains("if $z0 == 0 goto $z0 = interfaceinvoke $r4.<java.util.Iterator: boolean hasNext()>()"))
                            judgeisUrlWhiteListed.add("hasNext");
                        if(u.toString().contains("$r2 = r0.<org.apache.cordova.Whitelist: java.util.ArrayList whiteList>"))
                            judgeisUrlWhiteListed.add("ArrayList");
                        if(u.toString().contains("if $r2 != null goto $r3 = staticinvoke <android.net.Uri: android.net.Uri parse(java.lang.String)>($r1)"))
                            judgeisUrlWhiteListed.add("parse");
                    }
                }
                if (judgeXmlParse.size() >= 3) {
                    JSONObject subobj = new JSONObject();
                    subobj.put("name", "CustomConfigXmlParser");
                    subobj.put("location", c.getName());
                    subobj.put("signature", m.getSignature());
                    obj.accumulate("Whitelist method", subobj);
                }
                if (judgeaddWhiteListEntry.size() == 1) {
                    JSONObject subobj = new JSONObject();
                    subobj.put("name", "addWhiteListEntry");
                    subobj.put("location", c.getName());
                    subobj.put("signature", m.getSignature());
                    obj.accumulate("Whitelist method", subobj);
                }
                if (judgeisUrlWhiteListed.size() == 3) {
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
