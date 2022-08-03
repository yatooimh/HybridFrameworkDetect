package com.zzy.analyzeapk;

import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.infoflow.android.SetupApplication;
import soot.options.Options;
import soot.util.Chain;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import static java.util.Arrays.asList;

import java.util.Collections;
import java.util.Map;
import java.util.Vector;

import com.zzy.analyzeapk.cg.CallGraphUtils;

public class Util {
    public static int directoryindex = 0;
    public static int fileindex = 0;
    public static String rootDir = "/home/miniprogram/r6010/download_apks";//  "D:\\FDU\\laboratory\\labs-master\\soot\\apks\\testapk"
    public static String targetDir;
    public static Vector<String> directory_vector = new Vector<>();
    public static Vector<String> file_vector = new Vector<>();
    public static JSONObject jsonoutcome = new JSONObject();

    public static void setSootConfig() {
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_soot_classpath("rt.jar");
        Options.v().set_soot_classpath("jce.jar");
        //Options.v().set_soot_classpath("sootclasses-trunk-jar-with-dependencies.jar");
        Options.v().set_soot_classpath("soot-4.2.1-jar-with-dependencies.jar");
        Options.v().set_android_jars("platforms");
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_prepend_classpath(true);
        //Options.v().set_output_format(Options.output_format_none);//"-f", "n",

        Options.v().set_drop_bodies_after_load(false);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_process_dir(Collections.singletonList(targetDir));
        //Scene.v().loadClassAndSupport("java.lang.Object");
        Scene.v().loadNecessaryClasses();

        //Options.v().setPhaseOption("cg", "enabled:false");
        //app.constructCallgraph();
        //SootMethod entryPoint = app.getDummyMainMethod();
        //CallGraphUtils.buildCGbyCHA(EntryPoints.v().all());

        // Call-graph options
        Options.v().setPhaseOption("cg", "safe-newinstance:true");
        Options.v().setPhaseOption("cg.cha","enabled:false");
        // Enable SPARK call-graph construction
        Options.v().setPhaseOption("cg.spark","enabled:true");
        Options.v().setPhaseOption("cg.spark","verbose:true");
        Options.v().setPhaseOption("cg.spark","on-fly-cg:true");


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
        Options.v().setPhaseOption("wjtp.myanalysis","enabled:true");//"-p", "wjtp.myanalysis", "enabled:true",
    }

    public static void main(String[] args) throws IOException {
        File outcomefile = new File("/home/mnp2/zzy/outcome.json");
        //File outcomefile = new File(apkDir + "\\outcome.json");
        directory_vector = DetectFiles.getDirectory(rootDir);
        for(directoryindex = 0; directoryindex < directory_vector.size(); directoryindex++) {
            String apkDir = rootDir + File.separator + directory_vector.get(directoryindex);
            file_vector = DetectFiles.getfile(apkDir);//  "D:\\SDK\\platforms"
            //if(directory_vector.get(directoryindex).equals("music_audio")) file_vector.remove("com.moonvideo.android.resso.apk");
            int totalnum = file_vector.size(), processednum = 0;
            for (fileindex = 0; fileindex < file_vector.size(); fileindex++) {
                targetDir = apkDir + File.separator + file_vector.get(fileindex);
                try {
                    setSootConfig();
                    System.out.println("Analyzing " + file_vector.get(fileindex) + " located in " + directory_vector.get(directoryindex));
                    soot.Main.main(new String[]{"-f", "n"});
                    /*soot.Main.main(new String[]{
                            "-process-dir", apkDir + File.separator + file_vector.get(fileindex)
                    });*/
                } catch (Exception e) {
                    e.printStackTrace();
                }
                processednum += 1;
            }
            System.out.println("Having processed " + processednum + " apks, in " + totalnum + " altogether."+"\n");
        }
        FileWriter fw = new FileWriter(outcomefile);
        PrintWriter out = new PrintWriter(fw);
        out.write(jsonoutcome.toString());
        fw.close();
        out.close();
    }
}