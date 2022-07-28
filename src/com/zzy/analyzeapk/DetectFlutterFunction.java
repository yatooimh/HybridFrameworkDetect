package com.zzy.analyzeapk;

import org.json.JSONObject;
import soot.*;
import soot.util.Chain;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class DetectFlutterFunction {
    public static void findFlutterFunctions(Chain<SootClass> cs, JSONObject obj) {
        for(SootClass c : cs) {
            List<SootMethod> ms = c.getMethods();
            //Chain<SootField> fs = c.getFields();
            for (SootMethod m : ms) {
                Set<String> judgeParseDomain = new HashSet<>();
                Set<String> judgeNetworkPolicy = new HashSet<>();
                if (m.hasActiveBody()) {
                    Body b = m.getActiveBody();
                    final PatchingChain<Unit> units = b.getUnits();
                    for (Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext(); ) {
                        final Unit u = iter.next();
                        if (u.toString().contains("cleartextTrafficPermitted"))
                            judgeParseDomain.add("cleartextTrafficPermitted");
                        if (u.toString().contains("domain"))
                            judgeParseDomain.add("domain");
                        if (u.toString().contains("domain-config"))
                            judgeParseDomain.add("domain-config");

                        if (u.toString().contains("JSONArray"))
                            judgeNetworkPolicy.add("JSONArray");
                        if (u.toString().contains("XmlResourceParser"))
                            judgeNetworkPolicy.add("XmlResourceParser");
                        if (u.toString().contains("domain-config"))
                            judgeNetworkPolicy.add("domain-config");
                        if (u.toString().contains("io.flutter.network-policy") || u.toString().contains("NETWORK_POLICY_METADATA_KEY"))
                            judgeNetworkPolicy.add("io.flutter.network-policy");
                    }
                }
                if (judgeParseDomain.size() >= 3) {
                    JSONObject subobj = new JSONObject();
                    subobj.put("name", "parseDomainConfig");
                    subobj.put("location", c.getName());
                    subobj.put("signature", m.getSignature());
                    obj.accumulate("Whitelist method", subobj);
                }
                if (judgeNetworkPolicy.size() >= 4) {
                    JSONObject subobj = new JSONObject();
                    subobj.put("name", "getNetworkPolicy");
                    subobj.put("location", c.getName());
                    subobj.put("signature", m.getSignature());
                    obj.accumulate("Whitelist method", subobj);
                }
            }
        }
    }
}
