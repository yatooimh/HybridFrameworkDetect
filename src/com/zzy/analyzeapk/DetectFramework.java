package com.zzy.analyzeapk;

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeStmt;
import soot.options.Options;
import soot.util.Chain;

public class DetectFramework {
    static Set<String> frameworks = new HashSet<>(Arrays.asList("cordova", "flutter", "apicloud", "nativescript", "reactnative", "kerkee", "appcan"));

    public static void detectwhich(Chain<SootClass> cs, String apkPath) throws XmlPullParserException, IOException {
        boolean detectframework = false;
        String targetframework = "";
        String outcomeFromManifest = ManifestChecker.SearchManifest(apkPath);
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
            System.out.println("\n" + targetframework + " framework detected." + "\n");
            detectFunctions(targetframework, cs);
        }
    }

    public static void detectFunctions(String targetframework, Chain<SootClass> cs)
    {
        if(Objects.equals(targetframework, ""))
            return ;
        if(Objects.equals(targetframework, "cordova"))
            DetectCordovaFunction.findCordovaFunctions(cs);
        if(Objects.equals(targetframework, "apicloud"))
            DetectAPIcloudFunction.findAPIcloudFunctions(cs);
        if(Objects.equals(targetframework, "flutter"))
            DetectFlutterFunction.findFlutterFunctions(cs);
    }
}
