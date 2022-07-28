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
                        int parseflag = 0, hasNextflag = 0, matchflag = 0;
                        for(ValueBox box: u.getUseAndDefBoxes())
                        {
                            if(box.toString().contains("LinkedVariableBox")) parseflag++;
                            if(box.toString().contains("LinkedRValueBox(staticinvoke <android.net.Uri: android.net.Uri parse(java.lang.String)>")) parseflag++;
                            if(box.toString().contains("ImmediateBox")) parseflag++;

                            if(box.toString().contains("LinkedVariableBox")) hasNextflag++;
                            if(box.toString().contains("LinkedRValueBox(interfaceinvoke") && box.toString().contains("<java.util.Iterator: boolean hasNext()>")) hasNextflag++;
                            if(box.toString().contains("JimpleLocalBox")) hasNextflag++;

                            if(box.toString().contains("LinkedVariableBox")) matchflag++;
                            if(box.toString().contains("LinkedRValueBox") && box.toString().contains("boolean") && box.toString().contains("android.net.Uri")) matchflag++;
                            if(box.toString().contains("ImmediateBox")) matchflag++;
                            if(box.toString().contains("JimpleLocalBox")) matchflag++;
                        }
                        if(parseflag == 3) judgeisUrlWhiteListed.add("parse");
                        if(hasNextflag == 3) judgeisUrlWhiteListed.add("hasNext");
                        if(matchflag == 3) judgeisUrlWhiteListed.add("ArrayList");
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
