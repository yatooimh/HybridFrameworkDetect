package com.zzy.analyzeapk;

import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.options.Options;
import soot.util.Chain;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.Vector;

public class Util {
    public static int directoryindex = 0;
    public static int fileindex = 0;
    public static String rootDir = "D:\\FDU\\laboratory\\labs-master\\soot\\apks\\testapk";// "/home/miniprogram/r6010/download_apks"
    public static Vector<String> directory_vector = new Vector<>();
    public static Vector<String> file_vector = new Vector<>();
    public static JSONObject jsonoutcome = new JSONObject();

    public static void setSootConfig() {
        Options.v().set_src_prec(Options.src_prec_apk);
        //Options.v().set_output_format(Options.output_format_jimple);
        /*
        Options.v().set_soot_classpath("/home/mnp2/zzy/dependencies/rt.jar;/home/mnp2/zzy/dependencies/jce.jar;/home/mnp2/zzy/dependencies/sootclasses-trunk-jar-with-dependencies.jar");
        Options.v().set_android_jars("/home/mnp2/zzy/dependencies/platforms");
        */
        Options.v().set_soot_classpath("C:\\Program Files\\Java\\jdk1.8.0_271\\jre\\lib\\rt.jar;C:\\Program Files\\Java\\jdk1.8.0_271\\jre\\lib\\jce.jar;D:\\FDU\\laboratory\\labs-master\\soot\\sootclasses-trunk-jar-with-dependencies.jar");
        Options.v().set_android_jars("D:\\SDK\\platforms");
        PackManager.v().getPack("wjtp").add(
                new Transform("wjtp.myanalysis", new SceneTransformer() {
                    @Override
                    protected void internalTransform(String arg0, Map<String, String> arg1) {
                        Chain<SootClass> cs = Scene.v().getClasses();
                        try {
                            DetectFramework.detectwhich(cs, file_vector.get(fileindex));
                        } catch (XmlPullParserException | IOException e) {
                            e.printStackTrace();
                        }
                    }
                })
        );
    }

    public static void main(String[] args) throws IOException {
        File outcomefile = new File("outcome.json");
        //File outcomefile = new File(apkDir + "\\outcome.json");
        directory_vector = DetectFiles.getDirectory(rootDir);
        for(directoryindex = 0; directoryindex < directory_vector.size(); directoryindex++) {
            String apkDir = rootDir + File.separator + directory_vector.get(directoryindex);
            file_vector = DetectFiles.getfile(apkDir);//  "D:\\SDK\\platforms"
            for (fileindex = 0; fileindex < file_vector.size(); fileindex++) {
                setSootConfig();
                System.out.println("Analyzing " + file_vector.get(fileindex));
                soot.Main.main(new String[]{
                        "-w",
                        "-f", "n",
                        "-p", "wjtp.myanalysis", "enabled:true",
                        "-allow-phantom-refs",
                        "-pp",
                        "-process-dir", apkDir + File.separator + file_vector.get(fileindex),
                        "-process-multiple-dex"
                });
                G.reset();
            }
        }
        FileWriter fw = new FileWriter(outcomefile);
        PrintWriter out = new PrintWriter(fw);
        out.write(jsonoutcome.toString());
        fw.close();
        out.close();
    }
}
