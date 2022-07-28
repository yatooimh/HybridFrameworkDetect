package com.zzy.analyzeapk;

import org.json.JSONObject;
import soot.*;
import soot.util.Chain;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class DetectCordovaFunction {
    public static void findCordovaFunctions(Chain<SootClass> cs, JSONObject obj) {
        for(SootClass c : cs) {
            List<SootMethod> ms = c.getMethods();
            //Chain<SootField> fs = c.getFields();
            for (SootMethod m : ms) {
                Set<String> judgeXmlParse = new HashSet<>(), judgeaddWhiteListEntry = new HashSet<>(), judgeisUrlWhiteListed = new HashSet<>();
                Set<String> parseflag = new HashSet<>(), hasNextflag = new HashSet<>(), matchflag = new HashSet<>();
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

                        for(ValueBox box: u.getUseAndDefBoxes())
                        {
                            if(box.toString().contains("LinkedVariableBox")) parseflag.add("LinkedVariableBox");
                            if(box.toString().contains("LinkedRValueBox(staticinvoke <android.net.Uri: android.net.Uri parse(java.lang.String)>")) parseflag.add("LinkedRValueBox");
                            if(box.toString().contains("ImmediateBox")) parseflag.add("ImmediateBox");

                            if(box.toString().contains("LinkedVariableBox")) hasNextflag.add("LinkedVariableBox");
                            if(box.toString().contains("LinkedRValueBox(interfaceinvoke") && box.toString().contains("<java.util.Iterator: boolean hasNext()>")) hasNextflag.add("LinkedRValueBox");
                            if(box.toString().contains("JimpleLocalBox")) hasNextflag.add("JimpleLocalBox");

                            if(box.toString().contains("LinkedVariableBox")) matchflag.add("LinkedVariableBox");
                            if(box.toString().contains("LinkedRValueBox") && box.toString().contains("boolean") && box.toString().contains("android.net.Uri")) matchflag.add("LinkedRValueBox");
                            if(box.toString().contains("ImmediateBox")) matchflag.add("ImmediateBox");
                            if(box.toString().contains("JimpleLocalBox")) matchflag.add("JimpleLocalBox");
                        }
                        if(parseflag.size() == 3) judgeisUrlWhiteListed.add("parse");
                        if(hasNextflag.size() == 3) judgeisUrlWhiteListed.add("hasNext");
                        if(matchflag.size() == 3) judgeisUrlWhiteListed.add("ArrayList");
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
