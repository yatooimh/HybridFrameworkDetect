package com.zzy.analyzeapk;

import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.options.Options;
import soot.util.Chain;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Vector;

public class Util {
    static int fileindex = 0;
    static String apkPath = "D:\\FDU\\laboratory\\labs-master\\soot\\apks\\testapk";
    public static Vector<String> file_vector =  new Vector<String>();

    public static void setSootConfig() {
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_soot_classpath("C:\\Program Files\\Java\\jdk1.8.0_271\\jre\\lib\\rt.jar;C:\\Program Files\\Java\\jdk1.8.0_271\\jre\\lib\\jce.jar;D:\\FDU\\laboratory\\labs-master\\soot\\sootclasses-trunk-jar-with-dependencies.jar");
        Options.v().set_android_jars("D:\\SDK\\platforms");
        PackManager.v().getPack("wjtp").add(
                new Transform("wjtp.myanalysis", new SceneTransformer() {
                    @Override
                    protected void internalTransform(String arg0, Map<String, String> arg1) {
                        Chain<SootClass> cs = Scene.v().getClasses();
                        try {
                            DetectFramework.detectwhich(cs, apkPath+ File.separator+file_vector.get(fileindex));
                        } catch (XmlPullParserException | IOException e) {
                            e.printStackTrace();
                        }
                    }
                })
        );
    }

    public static void main(String[] args) {
        file_vector = DetectFiles.getfile(apkPath);//"-soot-class-path" "C:\\Users\\97896\\AppData\\Local\\Android\\android-sdk\\platforms" "D:\\SDK\\platforms"
        for(fileindex=0;fileindex<file_vector.size();fileindex++) {
            setSootConfig();
            System.out.println("Analyzing " + file_vector.get(fileindex) + "\n");
            soot.Main.main(new String[]{
                "-w",
                "-f", "J",
                "-p", "wjtp.myanalysis", "enabled:true",
                "-allow-phantom-refs",
                "-pp",
                "-process-dir", apkPath+ File.separator+file_vector.get(fileindex),
                "-process-multiple-dex"
            });
            G.reset();
        }
    }
}
