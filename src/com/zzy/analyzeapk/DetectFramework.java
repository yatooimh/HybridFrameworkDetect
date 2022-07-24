package com.zzy.analyzeapk;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

import com.sun.xml.internal.ws.util.UtilException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeStmt;
import soot.options.Options;
import soot.util.Chain;

public class DetectFramework {
    static Set<String> frameworks = new HashSet<>(Arrays.asList("cordova", "flutter", "apicloud", "nativescript", "reactnative", "kerkee", "appcan"));

    public static void detectwhich(Chain<SootClass> cs, String apkName) throws XmlPullParserException, IOException {
        boolean detectframework = false;
        String targetframework = "";
        String outcomeFromManifest = ManifestChecker.SearchManifest(Util.apkDir + File.separator + apkName);
        if(!outcomeFromManifest.equals(""))
        {
            detectframework = true;
            targetframework = outcomeFromManifest;
        }
        else {
            for (SootClass c : cs) {
                for (String framework : frameworks) {
                    if (!detectframework && c.getName().toLowerCase().contains(framework)) {
                        targetframework = framework;
                        detectframework = true;
                        break;
                    }
                }
            }
        }
        if(detectframework) {
            JSONObject subobj = new JSONObject();
            subobj.put("framework", targetframework);
            //System.out.println("\n" + targetframework + " framework detected." + "\n");
            detectFunctions(targetframework, cs, subobj);
            Util.jsonoutcome.accumulate(apkName, subobj);
        }
    }

    public static void detectFunctions(String targetframework, Chain<SootClass> cs, JSONObject obj) throws IOException {
        if(Objects.equals(targetframework, ""))
            return ;
        if(Objects.equals(targetframework, "cordova"))
            DetectCordovaFunction.findCordovaFunctions(cs, obj);
        if(Objects.equals(targetframework, "apicloud"))
            DetectAPIcloudFunction.findAPIcloudFunctions(cs, obj);
        if(Objects.equals(targetframework, "flutter"))
            DetectFlutterFunction.findFlutterFunctions(cs, obj);
    }
}
