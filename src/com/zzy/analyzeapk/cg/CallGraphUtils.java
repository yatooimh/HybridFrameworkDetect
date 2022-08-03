package com.zzy.analyzeapk.cg;

//import constant.StrawPointsDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.options.Options;
import soot.util.queue.QueueReader;
//import util.StringUtil;

import java.util.*;

/**
 * @program: AppAnalyze
 * @description: 提供调用图的一些基本功能
 * @author: Ms, Lkk, Sft
 * @create: 2022-02-28 12:01
 **/
public class CallGraphUtils {

    private static final Logger logger= LoggerFactory.getLogger(CallGraphUtils.class);

    public static final String SPARK="spark";
    public static final String CHA="cha";
    public static final String RTA="rta";
    public static final String VTA="vta";

    

    private static void resetCallGraph(){
        Scene.v().releaseCallGraph();
        Scene.v().releasePointsToAnalysis();
        Scene.v().releaseReachableMethods();
        G.v().resetSpark();
    }
    public static void constructCallGraphConfig(String callgraphAlgorithm){
        switch (callgraphAlgorithm){
            case SPARK:
                soot.options.Options.v().setPhaseOption("cg.spark", "on");
                break;
            case CHA:
                soot.options.Options.v().setPhaseOption("cg.cha", "on");
                break;
            case RTA:
                soot.options.Options.v().setPhaseOption("cg.spark", "on");
                soot.options.Options.v().setPhaseOption("cg.spark", "rta:true");
                soot.options.Options.v().setPhaseOption("cg.spark", "on-fly-cg:false");
                break;
            case VTA:
                soot.options.Options.v().setPhaseOption("cg.spark", "on");
                Options.v().setPhaseOption("cg.spark", "vta:true");
                break;
            default:
                throw new RuntimeException("Invalid callgraph algorithm");
        }
    }

    public static void constructCallGraph(String callgraphAlgorithm){
        resetCallGraph();
        constructCallGraphConfig(callgraphAlgorithm);
        PackManager.v().getPack("cg").apply();
    }

    public static boolean reachable(SootMethod method){
        ReachableMethods reachableMethods = Scene.v().getReachableMethods();
        return reachableMethods.contains(method);
    }
/*
    public static boolean isMethodReachable2Target(SootMethod begin, List<String> targetMethodList){
        QueueReader<MethodOrMethodContext> listener =
                Scene.v().getReachableMethods().listener();
        while (listener.hasNext()){
            String signature = listener.next().method().getSignature();
            if(targetMethodList.contains(signature)|| StringUtil.isMatch(signature,StrawPointsDefinition.COLLECTIONS_STRAWPOINT_REGEX))
                return true;

        }
        return false;

    }*/
    public static boolean isMethodReachable2Target(SootMethod begin, String targetMethod){
        QueueReader<MethodOrMethodContext> listener =
                Scene.v().getReachableMethods().listener();
        while (listener.hasNext()){
            String subSignature = listener.next().method().getSubSignature();
            if(targetMethod.equals(subSignature))
                return true;
        }
        return false;
    }

    public static HashMap<SootMethod, Unit> findTargetMethodInvokeInICFG(SootMethod method,String targetMethod){
        //寻找ICFG中满足条件的语句
        HashMap<SootMethod,Unit> res=new HashMap<>();
        QueueReader<MethodOrMethodContext> listener =
                Scene.v().getReachableMethods().listener();
        SootMethod target=null;
        while (listener.hasNext()){
            SootMethod sootMethod = listener.next().method();
            if(sootMethod.getSubSignature().equals(targetMethod)){
                target=sootMethod;
                break;
            }
        }
        Iterator<Edge> edges = Scene.v().getCallGraph().edgesInto(target);
        while (edges.hasNext()){
            SootMethod m = edges.next().getTgt().method();
            if(m.isConcrete()){
                for(Unit unit:m.retrieveActiveBody().getUnits()){
                    if(unit instanceof AssignStmt){
                        AssignStmt assignStmt = (AssignStmt) unit;
                        if(assignStmt.containsInvokeExpr()) {
                            if (assignStmt.getInvokeExpr().getMethod().getSubSignature().equals(targetMethod)) {
                                res.put(m, unit);
                            }
                        }
                    }
                }
            }
        }
        return res;

    }


    //用于找到从entrypoint到达目标方法的所有调用路径
    public static void findTargetMethod(SootMethod method, HashSet<String> targetMethod, String mode, List<CallSite> callStack, int max_depth, int depth, HashSet<List<CallSite>> paths) {
        if(!Scene.v().hasCallGraph())
            throw new RuntimeException("No CallGraph in Scence");
        if (depth > max_depth)
            return;
        for (CallSite callSite : callStack) {
            if (callSite.caller.getSignature().equals(method.getSignature()))
                return;
        }
        if (mode.equals("Signature") && targetMethod.contains(method.getSignature())) {
            paths.add(callStack);
        } else if (mode.equals("SubSignature") && targetMethod.contains(method.getSubSignature())) {
            logger.info("找到相关调用");
            paths.add(callStack);
        }
        CallGraph callGraph = Scene.v().getCallGraph();
        Iterator<Edge> edgeIterator = callGraph.edgesOutOf(method);
        while (edgeIterator.hasNext()) {

            Edge next = edgeIterator.next();
            List<CallSite> addedCallStack = new ArrayList<>(callStack);
            addedCallStack.add(new CallSite(next.src(), next.srcUnit(), -1));
            findTargetMethod(next.tgt(), targetMethod, mode, addedCallStack, max_depth, depth + 1, paths);
        }
    }

    //用于找到从targetMethod到entrypoint的所有调用路径
    public static void findEntryMethod(SootMethod method, HashSet<String> entryMethod, String mode, List<CallSite> callStack, int max_depth, int depth, HashSet<List<CallSite>> paths, boolean isMustFoundEntry) {
        //剪枝
        if(!Scene.v().hasCallGraph())
            throw new RuntimeException("No CallGraph in Scene");
        if (method.getSubSignature().equals("void run()") && method.getDeclaringClass().getSuperclass().getName().equals("java.lang.Object"))
            return;
        if (depth > max_depth) {
            if (!isMustFoundEntry)
                paths.add(callStack);
            return;
        }
        if (mode.equals("Signature") && entryMethod.contains(method.getSignature())) {
            paths.add(callStack);
            return;
        } else if (mode.equals("SubSignature") && entryMethod.contains(method.getSubSignature())) {
            paths.add(callStack);
            return;
        }
        CallGraph callGraph = Scene.v().getCallGraph();
        Iterator<Edge> edgeIterator = callGraph.edgesInto(method);
        while (edgeIterator.hasNext()) {
            Edge next = edgeIterator.next();
            List<CallSite> addedCallStack = new ArrayList<>(callStack);
            //检查是否有环
            if (callStack.contains(new CallSite(next.src(), next.srcUnit(), -1)))
                continue;
            addedCallStack.add(new CallSite(next.src(), next.srcUnit(), -1));
            findEntryMethod(next.src(), entryMethod, mode, addedCallStack, max_depth, depth + 1, paths, isMustFoundEntry);
        }
    }

    public static boolean isSystemClass(String clsName) {
        if (clsName.startsWith("java.") || clsName.startsWith("javax."))
            return true;
        if (clsName.startsWith("android.") || clsName.startsWith("androidx.") || clsName.startsWith("com.google.") || clsName.startsWith("com.android."))
            return true;
        if (clsName.startsWith("jdk"))
            return true;
        if (clsName.startsWith("sun."))
            return true;
        if (clsName.startsWith("org.omg") || clsName.startsWith("org.w3c.dom"))
            return true;
        return false;
    }

    public static void buildCGbyCHA(List<SootMethod> entrypoints) throws RuntimeException{
        Queue<SootMethod> worklist = new LinkedList<>(entrypoints);
        HashSet<SootMethod> reachableMethod=new HashSet<>();
        CallGraph cg = new CallGraph();
        Scene.v().setEntryPoints(entrypoints);
        while (!worklist.isEmpty()){
            SootMethod poll = worklist.poll();
            if(reachableMethod.contains(poll))
                continue;
            reachableMethod.add(poll);

            if(isSystemClass(poll.getDeclaringClass().getName()))
                continue;
            if(poll.isPhantom())
                continue;
            if(poll.isNative())
                continue;
            for(Unit u:poll.retrieveActiveBody().getUnits()){
                InvokeExpr invokeExpr=null;
                if(u instanceof InvokeStmt){
                    InvokeStmt invokeStmt = (InvokeStmt) u;
                    invokeExpr = invokeStmt.getInvokeExpr();
                }

                if(u instanceof AssignStmt){
                    AssignStmt assignStmt = (AssignStmt) u;
                    if(assignStmt.containsInvokeExpr())
                        invokeExpr=assignStmt.getInvokeExpr();
                }

                if(invokeExpr==null)
                    continue;
                Kind kind=Kind.CLINIT;

                HashSet<SootMethod> targetMethods = new HashSet<>();

                if (invokeExpr instanceof StaticInvokeExpr) {
                    targetMethods.add(invokeExpr.getMethod());
                    kind=Kind.CLINIT;
                }else {
                    int size = invokeExpr.getUseBoxes().size();
                    Type type = invokeExpr.getUseBoxes().get(size - 1).getValue().getType();
                    SootClass cls = Scene.v().getSootClass(type.toString());

                    if (invokeExpr instanceof SpecialInvokeExpr) {

                        SootMethod method = dispatchConcrete(cls, invokeExpr.getMethod());
                        if (method != null)
                            targetMethods.add(method);
                        kind=Kind.SPECIAL;
                    }

                    if ((invokeExpr instanceof InterfaceInvokeExpr) || (invokeExpr instanceof VirtualInvokeExpr)) {
                        String name = invokeExpr.getMethod().getName();
                        Type instancType = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size() - 1).getValue().getType();
                        SootClass sootClass = Scene.v().getSootClass(instancType.toString());
                        String superClassName = sootClass.getSuperclass().getName();
                        if((name.equals("run")&&sootClass.implementsInterface("java.lang.Runnable"))||(name.equals("start")&&(superClassName.equals("java.lang.Thread")||sootClass.getName().equals("java.lang.Thread")))||
                                (name.equals("execute")&&superClassName.equals("android.os.AsyncTask"))||(name.equals("post")&&superClassName.equals("android.os.Handler"))) {
                            //我们要处理异步的问题
                            SootMethod asyncMethod = getAsyncMethod(poll, invokeExpr);
                            if(asyncMethod!=null) {
                                targetMethods.add(asyncMethod);
                                kind=Kind.ASYNCTASK;
                            }
                        }else {
                            targetMethods.addAll(dispatchAbstract(cls, invokeExpr.getMethod()));
                            kind = Kind.VIRTUAL;
                        }
                    }
                }

                for(SootMethod target:targetMethods){
                    Edge edge = new Edge(poll, u, target,kind);
                    cg.addEdge(edge);
                }
                worklist.addAll(targetMethods);
            }
        }
        Scene.v().setCallGraph(cg);
    }

    public static SootMethod getAsyncMethod(SootMethod method,InvokeExpr invokeExpr){
        SootMethod apiMethod = invokeExpr.getMethod();
        String apiName = apiMethod.getName();
        String apiSig = apiMethod.getSignature();
        Value value = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size() - 1).getValue();
        Type type = value.getType();
        SootClass sc = Scene.v().getSootClass(type.toString());
        if(apiSig.equals("<java.lang.Thread: void start()>")){
            //1、Thread.start形式启动的
            //我们假设该方法的初始化在该方法中完成
            for(Unit u:method.retrieveActiveBody().getUnits()){
                if(u instanceof InvokeStmt){
                    InvokeExpr invokeExpr1 = ((InvokeStmt) u).getInvokeExpr();
                    if(invokeExpr1.getUseBoxes().get(invokeExpr1.getUseBoxes().size()-1).getValue().equals(value)&&
                            invokeExpr1.getMethod().getName().equals("<init>")){
                        Type runnableType = invokeExpr1.getArg(0).getType();
                        return Scene.v().getSootClass(runnableType.toString()).getMethodByNameUnsafe("run");
                    }
                }
            }
        }else if(apiName.equals("start")&&sc.hasSuperclass()&&sc.getSuperclass().getName().equals("java.lang.Thread")){
            //2、如果是Thread的子类的形式
            return sc.getMethodByNameUnsafe("run");

        }else if(apiName.equals("run")&&sc.implementsInterface("java.lang.Runnable")){
            return sc.getMethodByNameUnsafe("run");
        }else if(apiName.equals("post")&&sc.hasSuperclass()&&sc.getSuperclass().getName().equals("android.os.Handler")){
            Type runnableType = invokeExpr.getArg(0).getType();
            return Scene.v().getSootClass(runnableType.toString()).getMethodByNameUnsafe("run");
        }else if(apiName.equals("execute")&&sc.hasSuperclass()&&sc.getSuperclass().getName().equals("android.os.AsyncTask")){
            for (SootMethod m : sc.getMethods()) {
                if (m.getName().equals("doInBackground")) {
                    boolean flag=true;
                    for (Unit uu : m.retrieveActiveBody().getUnits())
                        if (uu.toString().contains("doInBackground")) {
                            flag = false;
                            break;
                        }
                    if(flag) {
                        return m;
                    }
                }

            }
        }
        return null;
    }

    //判断m是不是对于cls对象可见
    public static boolean isVisible(SootMethod m,SootClass cls){
        FastHierarchy hierarchy = Scene.v().getOrMakeFastHierarchy();
        if(m.isPublic()){
            //如果是public对所有子类都是可见的
            return true;
        }else if(m.isPrivate()){
            //如果是private则只有自己的类可见
            return m.getDeclaringClass().getName().equals(cls.getName());
        }else{
            return m.isProtected()? hierarchy.canStoreClass(cls,m.getDeclaringClass()) : cls.getJavaPackageName().equals(m.getDeclaringClass().getJavaPackageName());
        }
    }



    //
    public static SootMethod dispatchConcrete(SootClass cls,SootMethod method){
        String subSignature = method.getSubSignature();
        do {
            SootMethod m = cls.getMethodUnsafe(subSignature);
            if (m!=null) {
                if(m.isConcrete()&&isVisible(method,cls)) {
                    return m;
                }else {
                    return null;
                }
            }
            cls=cls.getSuperclassUnsafe();
        }while (cls!=null);
        return null;
    }

    //
    public static HashSet<SootMethod> dispatchAbstract(SootClass cls,SootMethod method){
        HashSet<SootMethod> targetMethod=new HashSet<>();
        Queue<SootClass> worklist=new LinkedList<>();
        worklist.add(cls);
        FastHierarchy hierarchy = Scene.v().getOrMakeFastHierarchy();
        while (!worklist.isEmpty()){
            SootClass currentClass = worklist.poll();
            if(currentClass==null)
                continue;
            if(currentClass.isInterface()){
                worklist.addAll(hierarchy.getAllImplementersOfInterface(currentClass));
            }else {
                //在本类中寻找方法的实现
                SootMethod m = dispatchConcrete(currentClass, method);
                if(m!=null)
                    targetMethod.add(m);
                //找到本类的子类加入
                Collection<SootClass> subclassesOf = hierarchy.getSubclassesOf(currentClass);
                worklist.addAll(subclassesOf);
            }
        }
        return targetMethod;
    }

    public static HashSet<SootMethod> getMethod(Unit u){
        //根据语句获取它的
        HashSet<SootMethod> res=new HashSet<>();
        InvokeExpr invokeExpr=null;
        if(u instanceof InvokeStmt){
            InvokeStmt invokeStmt = (InvokeStmt) u;
            invokeExpr = invokeStmt.getInvokeExpr();
        }

        if(u instanceof AssignStmt){
            AssignStmt assignStmt = (AssignStmt) u;
            if(assignStmt.containsInvokeExpr())
                invokeExpr=assignStmt.getInvokeExpr();
        }
        if(invokeExpr==null)
            return res;
        if (invokeExpr instanceof StaticInvokeExpr) {
            res.add(invokeExpr.getMethod());
        }else {
            int size = invokeExpr.getUseBoxes().size();
            Type type = invokeExpr.getUseBoxes().get(size - 1).getValue().getType();
            SootClass cls = Scene.v().getSootClass(type.toString());

            if (invokeExpr instanceof SpecialInvokeExpr) {
                SootMethod method = dispatchConcrete(cls, invokeExpr.getMethod());
                if (method != null)
                    res.add(method);
            }

            if ((invokeExpr instanceof InterfaceInvokeExpr) || (invokeExpr instanceof VirtualInvokeExpr)) {
                res.addAll(dispatchAbstract(cls, invokeExpr.getMethod()));
            }
        }
        return res;
    }





}
