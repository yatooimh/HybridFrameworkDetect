package com.zzy.analyzeapk;

import java.io.File;
import java.util.Vector;

public class DetectFiles {
    public static Vector<String> getDirectory(String targetPath) {
        Vector<String> directory_vec = new Vector<>();
        File file = new File(targetPath);
        File[] tempList = file.listFiles();
        assert tempList != null;
        for (File value : tempList) {
            if (value.isDirectory()) {
                    directory_vec.addElement(value.getName());
            }
        }
        return directory_vec;
    }
    public static Vector<String> getfile(String appDirPath){
        Vector<String> file_vec = new Vector<>();
        File file = new File(appDirPath);
        File[] tempList = file.listFiles();
        assert tempList != null;
        for (File value : tempList) {
            if (value.isFile()) {
                int lenname = value.getName().length();
                if (value.getName().substring(lenname - 4).equals(".apk")) {
                    file_vec.addElement(value.getName());
                }
            }
        }
        return file_vec;
    }
}
