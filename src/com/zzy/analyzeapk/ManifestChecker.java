package com.zzy.analyzeapk;

import org.xmlpull.v1.XmlPullParserException;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.ProcessManifest;

import java.io.IOException;
import java.util.List;


public class ManifestChecker
{
    public static String SearchManifest(String apkPath) throws IOException, XmlPullParserException
    {
        ProcessManifest processManifest = new ProcessManifest(apkPath);

        //apicloud
        List<AXmlNode> metaNodes1 = processManifest.getAXml().getNodesWithTag("action");
        for(AXmlNode metaNode : metaNodes1)
        {
            if(metaNode.getAttribute("name").toString().contains("apicloud")) {
                return "apicloud";
            }
        }

        //flutter
        List<AXmlNode> metaNodes2 = processManifest.getAXml().getNodesWithTag("meta-data");
        for(AXmlNode metaNode : metaNodes2)
        {
            if(metaNode.getAttribute("name").toString().contains("flutter"))
                 return "flutter";
        }

        //NativeScript
        List<AXmlNode> metaNodes3 = processManifest.getAXml().getNodesWithTag("activity");
        for(AXmlNode metaNode : metaNodes3)
        {
            if(metaNode.getAttribute("name").toString().contains("NativeScriptActivity")) {
                return "nativescript";
            }
        }

        //reactnative
        List<AXmlNode> metaNodes4 = processManifest.getAXml().getNodesWithTag("activity");
        for(AXmlNode metaNode : metaNodes4)
        {
            if(metaNode.getAttribute("name").toString().contains("com.facebook.react"))
                return "reactnative";
        }

        //kerkee
        List<AXmlNode> metaNodes5 = processManifest.getAXml().getNodesWithTag("activity");
        for(AXmlNode metaNode : metaNodes5)
        {
            if(metaNode.getAttribute("name").toString().contains("com.kercer.kerkee"))
                return "kerkee";
        }

        //cordova(appMobi)
        List<AXmlNode> metaNodes6 = processManifest.getAXml().getNodesWithTag("service");
        for(AXmlNode metaNode : metaNodes6)
        {
            if(metaNode.getAttribute("name").toString().contains("phonegap") || metaNode.getAttribute("name").toString().contains("cordova"))
                return "cordova";
        }
        return "";
    }
}
