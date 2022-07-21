package com.zzy.analyzeapk;

import soot.*;
import soot.util.Chain;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class DetectAPIcloudFunction {
    public static void findAPIcloudFunctions(Chain<SootClass> cs) {
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
                    System.out.println("Found a Whitelist method: addWhiteListEntry");
                    System.out.println("Exist in the class: " + c.getName());
                    System.out.println("Method name is: " + m.getSignature() + "\n");
                }
                if (judgeisUrlWhiteListed.size() == 4) {
                    System.out.println("Found a Whitelist method: isUrlWhiteListed");
                    System.out.println("Exist in the class: " + c.getName());
                    System.out.println("Method name is: " + m.getSignature() + "\n");
                }
            }
        }
    }
}
