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
        log(Log.INFO, TAG, "Hooking Alipay NFC detection");
        hookHasSystemFeature(param);
        hookGetSystemAvailableFeatures(param);
        hookNfcAdapter();
        hookNfcManager();
        hookGetSystemService(param);
        hookServiceManager(param);
        hookSettings(param);
    }

    // ── 1. hasSystemFeature ───────────────────────────────────────────────────

    private void hookHasSystemFeature(PackageLoadedParam param) {
        try {
            Class<?> appPmClass = param.getDefaultClassLoader()
                    .loadClass("android.app.ApplicationPackageManager");

            Method hasFeature1 = appPmClass.getMethod("hasSystemFeature", String.class);
            hook(hasFeature1).intercept(chain -> {
                if (isNfcFeature((String) chain.getArg(0))) {
                    log(Log.INFO, TAG, "Blocked hasSystemFeature(" + chain.getArg(0) + ")");
                    return false;
                }
                return chain.proceed();
            });

            Method hasFeature2 = appPmClass.getMethod("hasSystemFeature", String.class, int.class);
            hook(hasFeature2).intercept(chain -> {
                if (isNfcFeature((String) chain.getArg(0))) {
                    log(Log.INFO, TAG, "Blocked hasSystemFeature(" + chain.getArg(0) + ", ver)");
                    return false;
                }
                return chain.proceed();
            });

            log(Log.INFO, TAG, "hooked ApplicationPackageManager.hasSystemFeature");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook hasSystemFeature: " + t);
        }
    }

    // ── 2. getSystemAvailableFeatures – filter NFC from the list ─────────────

    private void hookGetSystemAvailableFeatures(PackageLoadedParam param) {
        try {
            Class<?> appPmClass = param.getDefaultClassLoader()
                    .loadClass("android.app.ApplicationPackageManager");
            Method m = appPmClass.getMethod("getSystemAvailableFeatures");
            hook(m).intercept(chain -> {
                Object result = chain.proceed();
                if (result == null) return null;
                // result is android.content.pm.FeatureInfo[]
                Class<?> featureInfoClass = param.getDefaultClassLoader()
                        .loadClass("android.content.pm.FeatureInfo");
                java.lang.reflect.Field nameField = featureInfoClass.getField("name");
                Object[] features = (Object[]) result;
                List<Object> filtered = new ArrayList<>();
                for (Object fi : features) {
                    String name = (String) nameField.get(fi);
                    if (!isNfcFeature(name)) {
                        filtered.add(fi);
                    } else {
                        log(Log.INFO, TAG, "Removed feature from list: " + name);
                    }
                }
                Object[] arr = (Object[]) java.lang.reflect.Array
                        .newInstance(featureInfoClass, filtered.size());
                return filtered.toArray(arr);
            });
            log(Log.INFO, TAG, "hooked getSystemAvailableFeatures");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook getSystemAvailableFeatures: " + t);
        }
    }

    // ── 3. NfcAdapter ─────────────────────────────────────────────────────────

    private void hookNfcAdapter() {
        try {
            Method m = NfcAdapter.class.getMethod("getDefaultAdapter", Context.class);
            hook(m).intercept(chain -> {
                log(Log.INFO, TAG, "Blocked NfcAdapter.getDefaultAdapter(Context)");
                return null;
            });
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook NfcAdapter.getDefaultAdapter(Context): " + t);
        }
        try {
            Method m = NfcAdapter.class.getMethod("getDefaultAdapter");
            hook(m).intercept(chain -> {
                log(Log.INFO, TAG, "Blocked NfcAdapter.getDefaultAdapter()");
                return null;
            });
        } catch (Throwable ignored) {}

        // isEnabled() – return false in case the adapter is obtained via other paths
        try {
            Method m = NfcAdapter.class.getMethod("isEnabled");
            hook(m).intercept(chain -> {
                log(Log.INFO, TAG, "Blocked NfcAdapter.isEnabled()");
                return false;
            });
        } catch (Throwable ignored) {}

        log(Log.INFO, TAG, "hooked NfcAdapter");
    }

    // ── 4. NfcManager ─────────────────────────────────────────────────────────

    private void hookNfcManager() {
        try {
            Method m = NfcManager.class.getMethod("getDefaultAdapter");
            hook(m).intercept(chain -> {
                log(Log.INFO, TAG, "Blocked NfcManager.getDefaultAdapter()");
                return null;
            });
            log(Log.INFO, TAG, "hooked NfcManager.getDefaultAdapter");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook NfcManager: " + t);
        }
    }

    // ── 5. Context.getSystemService("nfc") ────────────────────────────────────

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
            log(Log.INFO, TAG, "hooked ContextImpl.getSystemService");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook getSystemService: " + t);
        }
    }

    // ── 6. ServiceManager.getService / checkService ───────────────────────────

    private void hookServiceManager(PackageLoadedParam param) {
        try {
            Class<?> smClass = param.getDefaultClassLoader()
                    .loadClass("android.os.ServiceManager");

            for (String methodName : new String[]{"getService", "checkService"}) {
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
                    log(Log.INFO, TAG, "hooked ServiceManager." + methodName);
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "Failed to hook ServiceManager." + methodName + ": " + t);
                }
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to load ServiceManager: " + t);
        }
    }

    // ── 7. Settings.Global / Settings.Secure (nfc_on, etc.) ──────────────────

    private void hookSettings(PackageLoadedParam param) {
        ClassLoader cl = param.getDefaultClassLoader();
        for (String settingsClass : new String[]{"android.provider.Settings$Global",
                                                  "android.provider.Settings$Secure"}) {
            try {
                Class<?> cls = cl.loadClass(settingsClass);

                // getString
                try {
                    Method getString = cls.getMethod("getString",
                            android.content.ContentResolver.class, String.class);
                    hook(getString).intercept(chain -> {
                        String key = (String) chain.getArg(1);
                        if (key != null && key.toLowerCase().contains("nfc")) {
                            log(Log.INFO, TAG, "Blocked Settings.getString(" + key + ")");
                            return "0";
                        }
                        return chain.proceed();
                    });
                } catch (Throwable ignored) {}

                // getInt
                try {
                    Method getInt = cls.getMethod("getInt",
                            android.content.ContentResolver.class, String.class);
                    hook(getInt).intercept(chain -> {
                        String key = (String) chain.getArg(1);
                        if (key != null && key.toLowerCase().contains("nfc")) {
                            log(Log.INFO, TAG, "Blocked Settings.getInt(" + key + ")");
                            return 0;
                        }
                        return chain.proceed();
                    });
                } catch (Throwable ignored) {}

                // getInt with default
                try {
                    Method getIntDef = cls.getMethod("getInt",
                            android.content.ContentResolver.class, String.class, int.class);
                    hook(getIntDef).intercept(chain -> {
                        String key = (String) chain.getArg(1);
                        if (key != null && key.toLowerCase().contains("nfc")) {
                            log(Log.INFO, TAG, "Blocked Settings.getInt(" + key + ", def)");
                            return 0;
                        }
                        return chain.proceed();
                    });
                } catch (Throwable ignored) {}

                log(Log.INFO, TAG, "hooked " + settingsClass);
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Failed to hook " + settingsClass + ": " + t);
            }
        }
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private boolean isNfcFeature(String feature) {
        if (feature == null) return false;
        return feature.toLowerCase().contains("nfc");
    }
}