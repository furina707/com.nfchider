package com.nfchider;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.util.Log;

import androidx.annotation.NonNull;

import java.lang.reflect.Method;
import java.util.ArrayList;
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

                        // Check if it is a ParceledListSlice (binder proxy level) or simple array (PackageManager level)
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
                                    } catch (Throwable ignored) {}
                                }
                                filtered.add(fi);
                            }
                            Object[] arr = (Object[]) java.lang.reflect.Array.newInstance(
                                    result.getClass().getComponentType(), filtered.size());
                            return filtered.toArray(arr);
                        } else {
                            // ParceledListSlice support
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
                                            } catch (Throwable ignored) {}
                                        }
                                        filtered.add(fi);
                                    }
                                    java.lang.reflect.Constructor<?> constr = result.getClass().getConstructor(List.class);
                                    return constr.newInstance(filtered);
                                }
                            } catch (Throwable ignored) {}
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
                            } catch (Throwable ignored) {}
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
                                    } catch (Throwable ignored) {}
                                }
                                filtered.add(item);
                            }

                            if (isParceledListSlice) {
                                try {
                                    java.lang.reflect.Constructor<?> constr = result.getClass().getConstructor(List.class);
                                    return constr.newInstance(filtered);
                                } catch (Throwable ignored) {}
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
                            } catch (Throwable ignored) {}
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
                                    } catch (Throwable ignored) {}
                                }
                                filtered.add(ri);
                            }

                            if (isParceledListSlice) {
                                try {
                                    java.lang.reflect.Constructor<?> constr = result.getClass().getConstructor(List.class);
                                    return constr.newInstance(filtered);
                                } catch (Throwable ignored) {}
                            } else {
                                return filtered;
                            }
                        }
                        return result;
                    });
                }
            } catch (Throwable ignored) {}
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
                                Class<?> returnType = method.getReturnType();
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
                } catch (Throwable ignored) {}
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
                } catch (Throwable ignored) {}
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
            } catch (Throwable ignored) {}

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
                        } catch (Throwable ignored) {}
                    }
                } else {
                    try {
                        hook(method).intercept(chain -> {
                            String name = chain.getExecutable().getName();
                            Class<?> returnType = method.getReturnType();
                            log(Log.INFO, TAG, "Intercepted NfcAdapter method: " + name + ", return type: " + returnType.getName());
                            if (name.equals("getAdapterState")) {
                                return 1; // STATE_OFF
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
                    } catch (Throwable ignored) {}
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
                        Class<?> returnType = method.getReturnType();
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
                } catch (Throwable ignored) {}
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
                        Class<?> returnType = method.getReturnType();
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
                } catch (Throwable ignored) {}
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
                                        Class<?> returnType = method.getReturnType();
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
                        } catch (Throwable ignored) {}
                    }
                }
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Failed to hook " + settingsClass + ": " + t);
            }
        }
    }
}