package com.zzy.analyzeapk;

import soot.*;
import soot.util.Chain;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class DetectCordovaFunction {
    public static void findCordovaFunctions(Chain<SootClass> cs) {
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
                    System.out.println("Found a Whitelist method: CustomConfigXmlParser");
                    System.out.println("Exist in the class: " + c.getName());
                    System.out.println("Method name is: " + m.getSignature() + "\n");
                }
                if (judgeaddWhiteListEntry.size() == 1) {
                    System.out.println("Found a Whitelist method: addWhiteListEntry");
                    System.out.println("Exist in the class: " + c.getName());
                    System.out.println("Method name is: " + m.getSignature() + "\n");
                }
                if (judgeisUrlWhiteListed.size() == 3) {
                    System.out.println("Found a Whitelist method: isUrlWhiteListed");
                    System.out.println("Exist in the class: " + c.getName());
                    System.out.println("Method name is: " + m.getSignature() + "\n");
                }
            }
        }
    }
}
