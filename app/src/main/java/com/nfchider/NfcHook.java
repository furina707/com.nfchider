package com.nfchider;

import android.content.ContentResolver;
import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class NfcHook extends XposedModule {

    private static final String TAG = "NfcHider";
    private static final String TARGET_PKG = "com.eg.android.AlipayGphone";

    @Override
    public void onPackageLoaded(@NonNull PackageLoadedParam param) {
        if (!TARGET_PKG.equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "Hooking Alipay NFC detection with comprehensive advanced hooks");

        // 1. Hook PackageManager & IPackageManager reflectively
        hookPackageManager(param);

        // 2. Hook SystemProperties reflectively
        hookSystemProperties(param);

        // 3. Hook java.io.File to intercept NFC device/file queries
        hookFilesystem();

        // 4. Hook NfcAdapter reflectively for ALL methods
        hookNfcAdapter();

        // 5. Hook NfcManager reflectively for ALL methods
        hookNfcManager();

        // 6. Hook CardEmulation reflectively
        hookCardEmulation(param);

        // 7. Hook ContextImpl.getSystemService to return null for NFC services
        hookGetSystemService(param);

        // 8. Hook ServiceManager.getService / checkService / listServices
        hookServiceManager(param);

        // 9. Hook Settings (Global, Secure, System) reflectively
        hookSettings(param);

        // 10. Hook Runtime.exec() and ProcessBuilder to block shell-based detection
        hookProcessAndShell(param);

        // 11. Hook Class.forName to block loading NFC classes via reflection
        hookClassForName(param);

        // 12. Hook ContentResolver to block NFC content URIs
        hookContentResolver(param);

        // 13. Hook file reads on system config files that reveal NFC
        hookSystemConfigReads(param);
    }

    // ── 1. PackageManager & IPackageManager reflective hooks ──────────────────

    private void hookPackageManager(PackageLoadedParam param) {
        try {
            Class<?> appPmClass = param.getDefaultClassLoader()
                    .loadClass("android.app.ApplicationPackageManager");
            hookPackageManagerClass(appPmClass);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to load ApplicationPackageManager: " + t);
        }

        try {
            Class<?> ipmProxyClass = param.getDefaultClassLoader()
                    .loadClass("android.content.pm.IPackageManager$Stub$Proxy");
            hookPackageManagerClass(ipmProxyClass);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to load IPackageManager$Stub$Proxy: " + t);
        }
    }

    private void hookPackageManagerClass(Class<?> cls) {
        if (cls == null) return;
        for (Method method : cls.getDeclaredMethods()) {
            String name = method.getName();
            try {
                if (name.equals("getPackageInfo") || name.equals("getPackageInfoAsUser")) {
                    hook(method).intercept(chain -> {
                        if (chain.getArgs().size() > 0 && chain.getArg(0) instanceof String) {
                            String pkg = (String) chain.getArg(0);
                            if (pkg != null && pkg.toLowerCase().contains("nfc")) {
                                log(Log.INFO, TAG, "Blocked " + cls.getSimpleName() + "." + name + "(" + pkg + ")");
                                throw new android.content.pm.PackageManager.NameNotFoundException(pkg);
                            }
                        }
                        return chain.proceed();
                    });
                } else if (name.equals("getApplicationInfo") || name.equals("getApplicationInfoAsUser")) {
                    hook(method).intercept(chain -> {
                        if (chain.getArgs().size() > 0 && chain.getArg(0) instanceof String) {
                            String pkg = (String) chain.getArg(0);
                            if (pkg != null && pkg.toLowerCase().contains("nfc")) {
                                log(Log.INFO, TAG, "Blocked " + cls.getSimpleName() + "." + name + "(" + pkg + ")");
                                throw new android.content.pm.PackageManager.NameNotFoundException(pkg);
                            }
                        }
                        return chain.proceed();
                    });
                } else if (name.equals("hasSystemFeature")) {
                    hook(method).intercept(chain -> {
                        if (chain.getArgs().size() > 0 && chain.getArg(0) instanceof String) {
                            String feature = (String) chain.getArg(0);
                            if (feature != null && feature.toLowerCase().contains("nfc")) {
                                log(Log.INFO, TAG, "Blocked " + cls.getSimpleName() + ".hasSystemFeature(" + feature + ")");
                                return false;
                            }
                        }
                        return chain.proceed();
                    });
                } else if (name.equals("getSystemAvailableFeatures")) {
                    hook(method).intercept(chain -> {
                        Object result = chain.proceed();
                        if (result == null) return null;

                        if (result instanceof Object[]) {
                            Object[] features = (Object[]) result;
                            List<Object> filtered = new ArrayList<>();
                            for (Object fi : features) {
                                if (fi != null) {
                                    try {
                                        java.lang.reflect.Field nameField = fi.getClass().getField("name");
                                        String fName = (String) nameField.get(fi);
                                        if (fName != null && fName.toLowerCase().contains("nfc")) {
                                            log(Log.INFO, TAG, "Filtered out feature: " + fName);
                                            continue;
                                        }
                                    } catch (Throwable t) {
                                        log(Log.WARN, TAG, "Failed to get feature name field: " + t);
                                    }
                                }
                                filtered.add(fi);
                            }
                            Class<?> componentType = result.getClass().getComponentType();
                            if (componentType.equals(Object.class)) {
                                Object[] arr = (Object[]) java.lang.reflect.Array.newInstance(componentType, filtered.size());
                                return filtered.toArray(arr);
                            } else {
                                log(Log.WARN, TAG, "Unexpected component type: " + componentType.getName() + ", returning original result");
                                return result;
                            }
                        } else {
                            try {
                                Method getListMethod = result.getClass().getMethod("getList");
                                List<?> list = (List<?>) getListMethod.invoke(result);
                                if (list != null) {
                                    List<Object> filtered = new ArrayList<>();
                                    for (Object fi : list) {
                                        if (fi != null) {
                                            try {
                                                java.lang.reflect.Field nameField = fi.getClass().getField("name");
                                                String fName = (String) nameField.get(fi);
                                                if (fName != null && fName.toLowerCase().contains("nfc")) {
                                                    log(Log.INFO, TAG, "Filtered out binder feature: " + fName);
                                                    continue;
                                                }
                                            } catch (Throwable t) {
                                                log(Log.WARN, TAG, "Failed to get binder feature name: " + t);
                                            }
                                        }
                                        filtered.add(fi);
                                    }
                                    try {
                                        java.lang.reflect.Constructor<?> constr = result.getClass().getConstructor(List.class);
                                        return constr.newInstance(filtered);
                                    } catch (Throwable t) {
                                        log(Log.WARN, TAG, "Failed to reconstruct ParceledListSlice for binder features: " + t);
                                        return filtered;
                                    }
                                } catch (Throwable t) {
                                    log(Log.WARN, TAG, "Failed to process binder features list: " + t);
                                }
                            }
                        return result;
                    });
                } else if (name.equals("getInstalledPackages") || name.equals("getInstalledPackagesAsUser")
                        || name.equals("getInstalledApplications") || name.equals("getInstalledApplicationsAsUser")) {
                    hook(method).intercept(chain -> {
                        Object result = chain.proceed();
                        if (result == null) return null;

                        List<?> list = null;
                        boolean isParceledListSlice = false;
                        if (result instanceof List) {
                            list = (List<?>) result;
                        } else {
                            try {
                                Method getListMethod = result.getClass().getMethod("getList");
                                list = (List<?>) getListMethod.invoke(result);
                                isParceledListSlice = true;
                            } catch (Throwable t) {
                                log(Log.WARN, TAG, "Failed to get list from ParceledListSlice: " + t);
                            }
                        }

                        if (list != null) {
                            List<Object> filtered = new ArrayList<>();
                            for (Object item : list) {
                                if (item != null) {
                                    try {
                                        java.lang.reflect.Field pkgField = item.getClass().getField("packageName");
                                        String pkgName = (String) pkgField.get(item);
                                        if (pkgName != null && pkgName.toLowerCase().contains("nfc")) {
                                            log(Log.INFO, TAG, "Filtered out package: " + pkgName);
                                            continue;
                                        }
                                    } catch (Throwable t) {
                                        log(Log.WARN, TAG, "Failed to get package name field: " + t);
                                    }
                                }
                                filtered.add(item);
                            }

                            if (isParceledListSlice) {
                                try {
                                    java.lang.reflect.Constructor<?> constr = result.getClass().getConstructor(List.class);
                                    return constr.newInstance(filtered);
                                } catch (Throwable t) {
                                    log(Log.WARN, TAG, "Failed to reconstruct ParceledListSlice, returning filtered List: " + t);
                                    return filtered;
                                }
                            } else {
                                return filtered;
                            }
                        }
                        return result;
                    });
                } else if (name.equals("queryIntentActivities") || name.equals("queryIntentActivitiesAsUser")
                        || name.equals("queryIntentServices") || name.equals("queryIntentServicesAsUser")
                        || name.equals("queryIntentReceivers") || name.equals("queryIntentReceiversAsUser")) {
                    hook(method).intercept(chain -> {
                        if (chain.getArgs().size() > 0 && chain.getArg(0) instanceof android.content.Intent) {
                            android.content.Intent intent = (android.content.Intent) chain.getArg(0);
                            if (intent.getAction() != null && intent.getAction().toLowerCase().contains("nfc")) {
                                log(Log.INFO, TAG, "Blocked " + cls.getSimpleName() + "." + name + " for action: " + intent.getAction());
                                return new ArrayList<>();
                            }
                        }
                        Object result = chain.proceed();
                        if (result == null) return null;

                        List<?> list = null;
                        boolean isParceledListSlice = false;
                        if (result instanceof List) {
                            list = (List<?>) result;
                        } else {
                            try {
                                Method getListMethod = result.getClass().getMethod("getList");
                                list = (List<?>) getListMethod.invoke(result);
                                isParceledListSlice = true;
                            } catch (Throwable t) {
                                log(Log.WARN, TAG, "Failed to get list from ParceledListSlice for intent query: " + t);
                            }
                        }

                        if (list != null) {
                            List<Object> filtered = new ArrayList<>();
                            for (Object ri : list) {
                                if (ri != null) {
                                    try {
                                        java.lang.reflect.Field actField = ri.getClass().getField("activityInfo");
                                        Object info = actField.get(ri);
                                        if (info == null) {
                                            java.lang.reflect.Field srvField = ri.getClass().getField("serviceInfo");
                                            info = srvField.get(ri);
                                        }
                                        if (info == null) {
                                            java.lang.reflect.Field provField = ri.getClass().getField("providerInfo");
                                            info = provField.get(ri);
                                        }
                                        if (info != null) {
                                            java.lang.reflect.Field pkgField = info.getClass().getField("packageName");
                                            String pkgName = (String) pkgField.get(info);
                                            if (pkgName != null && pkgName.toLowerCase().contains("nfc")) {
                                                log(Log.INFO, TAG, "Filtered out intent resolve: " + pkgName);
                                                continue;
                                            }
                                        }
                                    } catch (Throwable t) {
                                        log(Log.WARN, TAG, "Failed to get resolve info fields: " + t);
                                    }
                                }
                                filtered.add(ri);
                            }

                            if (isParceledListSlice) {
                                try {
                                    java.lang.reflect.Constructor<?> constr = result.getClass().getConstructor(List.class);
                                    return constr.newInstance(filtered);
                                } catch (Throwable t) {
                                    log(Log.WARN, TAG, "Failed to reconstruct ParceledListSlice for intent resolve, returning filtered List: " + t);
                                    return filtered;
                                }
                            } else {
                                return filtered;
                            }
                        }
                        return result;
                    });
                }
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Failed to hook PackageManager method: " + t);
            }
        }
        log(Log.INFO, TAG, "hooked PackageManager class: " + cls.getName());
    }

    // ── 2. SystemProperties reflective hooks ─────────────────────────────────

    private void hookSystemProperties(PackageLoadedParam param) {
        try {
            Class<?> sysPropClass = param.getDefaultClassLoader()
                    .loadClass("android.os.SystemProperties");
            for (Method method : sysPropClass.getDeclaredMethods()) {
                try {
                    hook(method).intercept(chain -> {
                        if (chain.getArgs().size() > 0 && chain.getArg(0) instanceof String) {
                            String key = (String) chain.getArg(0);
                            if (key != null && key.toLowerCase().contains("nfc")) {
                                log(Log.INFO, TAG, "Blocked SystemProperties." + chain.getExecutable().getName() + "(" + key + ")");
                                Class<?> returnType = chain.getExecutable().getReturnType();
                                if (returnType.equals(boolean.class) || returnType.equals(Boolean.class)) {
                                    return false;
                                }
                                if (returnType.equals(int.class) || returnType.equals(Integer.class)) {
                                    return 0;
                                }
                                if (returnType.equals(long.class) || returnType.equals(Long.class)) {
                                    return 0L;
                                }
                                if (returnType.equals(String.class)) {
                                    if (chain.getArgs().size() > 1 && chain.getArg(1) instanceof String) {
                                        return chain.getArg(1);
                                    }
                                    return "";
                                }
                                if (chain.getArgs().size() > 1) {
                                    return chain.getArg(chain.getArgs().size() - 1);
                                }
                                return null;
                            }
                        }
                        return chain.proceed();
                    });
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "Failed to hook SystemProperties method: " + t);
                }
            }
            log(Log.INFO, TAG, "hooked android.os.SystemProperties reflectively");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook android.os.SystemProperties: " + t);
        }
    }

    // ── 3. Filesystem (java.io.File) hooks ───────────────────────────────────

    private void hookFilesystem() {
        try {
            Class<?> fileClass = java.io.File.class;
            String[] methodsToBlock = {"exists", "canRead", "canWrite", "isFile", "isDirectory"};
            for (String methodName : methodsToBlock) {
                try {
                    Method m = fileClass.getMethod(methodName);
                    hook(m).intercept(chain -> {
                        java.io.File file = (java.io.File) chain.getThisObject();
                        if (file != null) {
                            String path = file.getPath();
                            if (path != null && path.toLowerCase().contains("nfc")) {
                                log(Log.INFO, TAG, "Blocked File." + methodName + "() for path: " + path);
                                return false;
                            }
                        }
                        return chain.proceed();
                    });
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "Failed to hook File method: " + t);
                }
            }

            try {
                Method m = fileClass.getMethod("length");
                hook(m).intercept(chain -> {
                    java.io.File file = (java.io.File) chain.getThisObject();
                    if (file != null) {
                        String path = file.getPath();
                        if (path != null && path.toLowerCase().contains("nfc")) {
                            log(Log.INFO, TAG, "Blocked File.length() for path: " + path);
                            return 0L;
                        }
                    }
                    return chain.proceed();
                });
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Failed to hook File.length: " + t);
            }
            // Hook java.io.FileInputStream constructors to block reading NFC config files
            Class<?> fisClass = java.io.FileInputStream.class;
            try {
                java.lang.reflect.Constructor<?> constrString = fisClass.getConstructor(String.class);
                hook(constrString).intercept(chain -> {
                    String path = (String) chain.getArg(0);
                    if (path != null && path.toLowerCase().contains("nfc")) {
                        log(Log.INFO, TAG, "Blocked FileInputStream(String) for path: " + path);
                        throw new java.io.FileNotFoundException("NFC file blocked by Hider");
                    }
                    return chain.proceed();
                });
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Failed to hook FileInputStream(String): " + t);
            }

            try {
                java.lang.reflect.Constructor<?> constrFile = fisClass.getConstructor(java.io.File.class);
                hook(constrFile).intercept(chain -> {
                    java.io.File file = (java.io.File) chain.getArg(0);
                    if (file != null) {
                        String path = file.getPath();
                        if (path != null && path.toLowerCase().contains("nfc")) {
                            log(Log.INFO, TAG, "Blocked FileInputStream(File) for path: " + path);
                            throw new java.io.FileNotFoundException("NFC file blocked by Hider");
                        }
                    }
                    return chain.proceed();
                });
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Failed to hook FileInputStream(File): " + t);
            }

            log(Log.INFO, TAG, "hooked java.io.File and FileInputStream methods");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook java.io.File: " + t);
        }
    }

    // ── 4. NfcAdapter reflective hooks ───────────────────────────────────────

    private void hookNfcAdapter() {
        try {
            for (Method method : NfcAdapter.class.getDeclaredMethods()) {
                if (java.lang.reflect.Modifier.isStatic(method.getModifiers())) {
                    if (method.getReturnType().equals(NfcAdapter.class)) {
                        try {
                            hook(method).intercept(chain -> {
                                log(Log.INFO, TAG, "Blocked static NfcAdapter method returning adapter: " + chain.getExecutable().getName());
                                return null;
                            });
                        } catch (Throwable t) {
                            log(Log.WARN, TAG, "Failed to hook static NfcAdapter method: " + t);
                        }
                    }
                } else {
                    try {
                        hook(method).intercept(chain -> {
                            String name = chain.getExecutable().getName();
                            Class<?> returnType = chain.getExecutable().getReturnType();
                            log(Log.INFO, TAG, "Intercepted NfcAdapter method: " + name + ", return type: " + returnType.getName());
                            if (name.equals("getAdapterState")) {
                                return 1;
                            }
                            if (returnType.equals(boolean.class) || returnType.equals(Boolean.class)) {
                                return false;
                            }
                            if (returnType.isPrimitive()) {
                                if (returnType.equals(void.class)) {
                                    return null;
                                }
                                return 0;
                            }
                            return null;
                        });
                    } catch (Throwable t) {
                        log(Log.WARN, TAG, "Failed to hook NfcAdapter method: " + t);
                    }
                }
            }
            log(Log.INFO, TAG, "hooked NfcAdapter reflectively");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook NfcAdapter: " + t);
        }
    }

    // ── 5. NfcManager reflective hooks ───────────────────────────────────────

    private void hookNfcManager() {
        try {
            for (Method method : NfcManager.class.getDeclaredMethods()) {
                try {
                    hook(method).intercept(chain -> {
                        String name = chain.getExecutable().getName();
                        Class<?> returnType = chain.getExecutable().getReturnType();
                        log(Log.INFO, TAG, "Intercepted NfcManager method: " + name);
                        if (returnType.equals(NfcAdapter.class)) {
                            return null;
                        }
                        if (returnType.equals(boolean.class) || returnType.equals(Boolean.class)) {
                            return false;
                        }
                        if (returnType.isPrimitive()) {
                            if (returnType.equals(void.class)) {
                                return null;
                            }
                            return 0;
                        }
                        return null;
                    });
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "Failed to hook NfcManager method: " + t);
                }
            }
            log(Log.INFO, TAG, "hooked NfcManager reflectively");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook NfcManager: " + t);
        }
    }

    // ── 6. CardEmulation reflective hooks ────────────────────────────────────

    private void hookCardEmulation(PackageLoadedParam param) {
        try {
            Class<?> cardEmuClass = param.getDefaultClassLoader()
                    .loadClass("android.nfc.cardemulation.CardEmulation");
            for (Method method : cardEmuClass.getDeclaredMethods()) {
                try {
                    hook(method).intercept(chain -> {
                        String name = chain.getExecutable().getName();
                        Class<?> returnType = chain.getExecutable().getReturnType();
                        log(Log.INFO, TAG, "Intercepted CardEmulation method: " + name);
                        if (returnType.equals(boolean.class) || returnType.equals(Boolean.class)) {
                            return false;
                        }
                        if (returnType.isPrimitive()) {
                            if (returnType.equals(void.class)) {
                                return null;
                            }
                            return 0;
                        }
                        return null;
                    });
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "Failed to hook CardEmulation method: " + t);
                }
            }
            log(Log.INFO, TAG, "hooked android.nfc.cardemulation.CardEmulation reflectively");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to load android.nfc.cardemulation.CardEmulation: " + t);
        }
    }

    // ── 7. Context.getSystemService("nfc") ────────────────────────────────────

    private void hookGetSystemService(PackageLoadedParam param) {
        try {
            Class<?> ctxImplClass = param.getDefaultClassLoader()
                    .loadClass("android.app.ContextImpl");
            Method m = ctxImplClass.getMethod("getSystemService", String.class);
            hook(m).intercept(chain -> {
                String name = (String) chain.getArg(0);
                if (Context.NFC_SERVICE.equals(name)) {
                    log(Log.INFO, TAG, "Blocked getSystemService(nfc)");
                    return null;
                }
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook getSystemService: " + t);
        }

        try {
            Class<?> ctxImplClass = param.getDefaultClassLoader()
                    .loadClass("android.app.ContextImpl");
            Method mClass = ctxImplClass.getMethod("getSystemService", Class.class);
            hook(mClass).intercept(chain -> {
                Class<?> serviceClass = (Class<?>) chain.getArg(0);
                if (serviceClass != null && (NfcManager.class.getName().equals(serviceClass.getName()) 
                        || "android.nfc.NfcManager".equals(serviceClass.getName()) 
                        || "android.nfc.NfcAdapter".equals(serviceClass.getName()))) {
                    log(Log.INFO, TAG, "Blocked getSystemService(Class: " + serviceClass.getName() + ")");
                    return null;
                }
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook getSystemService(Class): " + t);
        }
    }

    // ── 8. ServiceManager.getService / checkService / listServices ────────────

    private void hookServiceManager(PackageLoadedParam param) {
        try {
            Class<?> smClass = param.getDefaultClassLoader()
                    .loadClass("android.os.ServiceManager");

            for (String methodName : new String[]{"getService", "checkService", "waitForService"}) {
                try {
                    Method m = smClass.getMethod(methodName, String.class);
                    hook(m).intercept(chain -> {
                        String name = (String) chain.getArg(0);
                        if (name != null && name.toLowerCase().contains("nfc")) {
                            log(Log.INFO, TAG, "Blocked ServiceManager." + methodName + "(" + name + ")");
                            return null;
                        }
                        return chain.proceed();
                    });
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "Failed to hook ServiceManager." + methodName + ": " + t);
                }
            }

            try {
                Method listServices = smClass.getMethod("listServices");
                hook(listServices).intercept(chain -> {
                    String[] services = (String[]) chain.proceed();
                    if (services == null) return null;
                    List<String> filtered = new ArrayList<>();
                    for (String s : services) {
                        if (s == null || !s.toLowerCase().contains("nfc")) {
                            filtered.add(s);
                        } else {
                            log(Log.INFO, TAG, "Removed service from listServices: " + s);
                        }
                    }
                    return filtered.toArray(new String[0]);
                });
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Failed to hook ServiceManager.listServices: " + t);
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to load ServiceManager: " + t);
        }
    }

    // ── 10. Runtime.exec() / ProcessBuilder shell command hooks ─────────────────

    private void hookProcessAndShell(PackageLoadedParam param) {
        // Hook ProcessBuilder.start()
        try {
            Class<?> pbClass = param.getDefaultClassLoader().loadClass("java.lang.ProcessBuilder");
            Method startMethod = pbClass.getMethod("start");
            hook(startMethod).intercept(chain -> {
                ProcessBuilder pb = (ProcessBuilder) chain.getThisObject();
                List<String> cmd = pb.command();
                if (cmd != null) {
                    for (String arg : cmd) {
                        if (arg != null && arg.toLowerCase().contains("nfc")) {
                            log(Log.INFO, TAG, "Blocked ProcessBuilder command containing nfc: " + String.join(" ", cmd));
                            // Return a dummy process that exits immediately
                            return new DummyProcess();
                        }
                    }
                    // Block getprop entirely - if it's used to check nfc props, block it
                    String cmdStr = String.join(" ", cmd).toLowerCase();
                    if (cmdStr.contains("getprop") && containsNfcPropertyCheck(cmd)) {
                        log(Log.INFO, TAG, "Blocked getprop command that may reveal NFC: " + String.join(" ", cmd));
                        return new DummyProcess();
                    }
                }
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook ProcessBuilder.start(): " + t);
        }

        // Hook Runtime.exec() methods
        try {
            Class<?> rtClass = param.getDefaultClassLoader().loadClass("java.lang.Runtime");
            for (Method m : rtClass.getDeclaredMethods()) {
                if (m.getName().equals("exec")) {
                    try {
                        hook(m).intercept(chain -> {
                            String cmdStr = "";
                            for (int i = 0; i < chain.getArgs().size(); i++) {
                                Object arg = chain.getArg(i);
                                if (arg instanceof String) {
                                    cmdStr = (String) arg;
                                } else if (arg instanceof String[]) {
                                    cmdStr = String.join(" ", (String[]) arg);
                                }
                            }
                            if (cmdStr.toLowerCase().contains("nfc")) {
                                log(Log.INFO, TAG, "Blocked Runtime.exec() containing nfc: " + cmdStr);
                                return new DummyProcess();
                            }
                            return chain.proceed();
                        });
                    } catch (Throwable t) {
                        log(Log.WARN, TAG, "Failed to hook Runtime.exec method: " + t);
                    }
                }
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook Runtime.exec(): " + t);
        }

        log(Log.INFO, TAG, "hooked ProcessBuilder and Runtime.exec");
    }

    private boolean containsNfcPropertyCheck(List<String> cmd) {
        for (String arg : cmd) {
            if (arg != null && (arg.toLowerCase().contains("nfc")
                    || arg.equals("ro.vendor.nfc")
                    || arg.equals("persist.nfc")))
                return true;
        }
        return false;
    }

    // Dummy process returned when blocking shell commands
    private static class DummyProcess extends Process {
        @Override public java.io.OutputStream getOutputStream() { return null; }
        @Override public java.io.InputStream getInputStream() { return new java.io.ByteArrayInputStream(new byte[0]); }
        @Override public java.io.InputStream getErrorStream() { return new java.io.ByteArrayInputStream(new byte[0]); }
        @Override public int waitFor() { return 0; }
        @Override public int exitValue() { return 0; }
        @Override public void destroy() {}
    }

    // ── 11. Class.forName() blocking hook ─────────────────────────────────────

    private void hookClassForName(PackageLoadedParam param) {
        try {
            Class<?> cls = param.getDefaultClassLoader().loadClass("java.lang.Class");
            for (Method m : cls.getDeclaredMethods()) {
                if (m.getName().equals("forName")) {
                    try {
                        hook(m).intercept(chain -> {
                            if (chain.getArgs().size() > 0 && chain.getArg(0) instanceof String) {
                                String className = (String) chain.getArg(0);
                                if (className != null && className.toLowerCase().contains("nfc")) {
                                    log(Log.INFO, TAG, "Blocked Class.forName(" + className + ")");
                                    throw new ClassNotFoundException("NFC class blocked");
                                }
                            }
                            return chain.proceed();
                        });
                    } catch (Throwable t) {
                        log(Log.WARN, TAG, "Failed to hook Class.forName method: " + t);
                    }
                }
            }
            log(Log.INFO, TAG, "hooked Class.forName for NFC blocking");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook Class.forName: " + t);
        }

        try {
            Class<?> clClass = param.getDefaultClassLoader().loadClass("java.lang.ClassLoader");
            for (Method m : clClass.getDeclaredMethods()) {
                if (m.getName().equals("loadClass")) {
                    try {
                        hook(m).intercept(chain -> {
                            if (chain.getArgs().size() > 0 && chain.getArg(0) instanceof String) {
                                String className = (String) chain.getArg(0);
                                if (className != null && className.toLowerCase().contains("nfc")) {
                                    log(Log.INFO, TAG, "Blocked ClassLoader.loadClass(" + className + ")");
                                    throw new ClassNotFoundException("NFC class blocked");
                                }
                            }
                            return chain.proceed();
                        });
                    } catch (Throwable t) {
                        log(Log.WARN, TAG, "Failed to hook ClassLoader.loadClass method: " + t);
                    }
                }
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook ClassLoader.loadClass: " + t);
        }
    }

    // ── 12. ContentResolver NFC URI blocking hook ─────────────────────────────

    private void hookContentResolver(PackageLoadedParam param) {
        try {
            Class<?> crClass = param.getDefaultClassLoader().loadClass("android.content.ContentResolver");
            for (Method m : crClass.getDeclaredMethods()) {
                String name = m.getName();
                if (name.equals("query") || name.equals("acquireContentProviderClient")) {
                    try {
                        hook(m).intercept(chain -> {
                            if (chain.getArgs().size() > 0) {
                                Object uri = chain.getArg(0);
                                if (uri != null && uri.toString().toLowerCase().contains("nfc")) {
                                    log(Log.INFO, TAG, "Blocked ContentResolver." + name + " for URI: " + uri);
                                    return null;
                                }
                            }
                            return chain.proceed();
                        });
                    } catch (Throwable t) {
                        log(Log.WARN, TAG, "Failed to hook ContentResolver method: " + t);
                    }
                }
            }
            log(Log.INFO, TAG, "hooked ContentResolver for NFC URI blocking");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook ContentResolver: " + t);
        }
    }

    // ── 13. System config file read hook (block NFC content from build.prop etc) ──

    private void hookSystemConfigReads(PackageLoadedParam param) {
        // Hook FileInputStream.read(byte[]) to filter NFC content from system config files
        try {
            Method readBytes = FileInputStream.class.getMethod("read", byte[].class);
            hook(readBytes).intercept(chain -> {
                FileInputStream fis = (FileInputStream) chain.getThisObject();
                // Check if this is a system config file that might contain NFC info
                String fdPath = getFilePathFromFis(fis);
                if (fdPath != null && isNfcLeakingConfigFile(fdPath)) {
                    int ret = (int) chain.proceed();
                    if (ret > 0) {
                        byte[] buf = (byte[]) chain.getArg(0);
                        String content = new String(buf, 0, ret, java.nio.charset.StandardCharsets.UTF_8);
                        String filtered = filterNfcLines(content);
                        if (!filtered.equals(content)) {
                            byte[] filteredBytes = filtered.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                            int copyLen = Math.min(filteredBytes.length, buf.length);
                            System.arraycopy(filteredBytes, 0, buf, 0, copyLen);
                            log(Log.INFO, TAG, "Filtered NFC content from: " + fdPath);
                            return copyLen;
                        }
                    }
                    return ret;
                }
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook FileInputStream.read(byte[]): " + t);
        }

        // Hook BufferedReader.readLine() for filtering NFC lines from config files
        try {
            Method readLine = BufferedReader.class.getMethod("readLine");
            hook(readLine).intercept(chain -> {
                BufferedReader br = (BufferedReader) chain.getThisObject();
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook BufferedReader.readLine: " + t);
        }

        log(Log.INFO, TAG, "hooked system config file reads");
    }

    private String getFilePathFromFis(FileInputStream fis) {
        try {
            Field pathField = FileInputStream.class.getDeclaredField("path");
            pathField.setAccessible(true);
            Object path = pathField.get(fis);
            if (path instanceof String) return (String) path;
            if (path instanceof File) return ((File) path).getPath();
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to get path from FileInputStream: " + t);
        }
        try {
            java.lang.reflect.Field fdField = fis.getClass().getDeclaredField("fd");
            fdField.setAccessible(true);
            Object fdObj = fdField.get(fis);
            if (fdObj != null) {
                String fdStr = fdObj.toString();
                if (fdStr.contains("/")) return fdStr.substring(fdStr.indexOf("/"));
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to get fd from FileInputStream: " + t);
        }
        return null;
    }

    private boolean isNfcLeakingConfigFile(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        return lower.contains("build.prop")
                || lower.contains("default.prop")
                || lower.contains("permissions")
                || lower.contains("libnfc")
                || lower.contains("nfc_config")
                || lower.contains("system_config")
                || lower.contains("device_features");
    }

    private String filterNfcLines(String content) {
        if (content == null || content.isEmpty()) return content;
        StringBuilder sb = new StringBuilder();
        String[] lines = content.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.toLowerCase().contains("nfc")) {
                continue; // Skip NFC lines
            }
            if (i < lines.length - 1) {
                sb.append(line).append("\n");
            } else {
                sb.append(line);
            }
        }
        return sb.toString();
    }

    // ── 9. Settings.Global / Settings.Secure / Settings.System reflective hooks ──

    private void hookSettings(PackageLoadedParam param) {
        ClassLoader cl = param.getDefaultClassLoader();
        for (String settingsClass : new String[]{"android.provider.Settings$Global",
                                                  "android.provider.Settings$Secure",
                                                  "android.provider.Settings$System"}) {
            try {
                Class<?> cls = cl.loadClass(settingsClass);
                for (Method method : cls.getDeclaredMethods()) {
                    if (method.getName().startsWith("get") && method.getParameterTypes().length >= 2) {
                        try {
                            hook(method).intercept(chain -> {
                                if (chain.getArgs().size() > 1 && chain.getArg(1) instanceof String) {
                                    String key = (String) chain.getArg(1);
                                    if (key != null && key.toLowerCase().contains("nfc")) {
                                        log(Log.INFO, TAG, "Blocked Settings method " + chain.getExecutable().getName() + "(" + key + ")");
                                        Class<?> returnType = chain.getExecutable().getReturnType();
                                        if (returnType.equals(boolean.class) || returnType.equals(Boolean.class)) {
                                            return false;
                                        }
                                        if (returnType.equals(int.class) || returnType.equals(Integer.class)) {
                                            return 0;
                                        }
                                        if (returnType.equals(long.class) || returnType.equals(Long.class)) {
                                            return 0L;
                                        }
                                        if (returnType.equals(float.class) || returnType.equals(Float.class)) {
                                            return 0f;
                                        }
                                        if (returnType.equals(String.class)) {
                                            return "0";
                                        }
                                        return null;
                                    }
                                }
                                return chain.proceed();
                            });
                        } catch (Throwable t) {
                            log(Log.WARN, TAG, "Failed to hook Settings method: " + t);
                        }
                    }
                }
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Failed to hook " + settingsClass + ": " + t);
            }
        }
    }
}