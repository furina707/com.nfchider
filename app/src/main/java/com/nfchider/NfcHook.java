package com.nfchider;

import android.content.Context;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class NfcHook implements IXposedHookLoadPackage {

    private static final String TAG = "NfcHider";
    private static final String TARGET_PKG = "com.eg.android.AlipayGphone";

    private static final String[] NFC_FEATURES = {
        "android.hardware.nfc",
        "android.hardware.nfc.any",
        "android.hardware.nfc.hce",
        "android.hardware.nfc.hcef",
        "android.hardware.nfc.off_host_card_emulation",
        "android.hardware.nfc.off_host_card_emulation_nfcf",
    };

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) {
            return;
        }

        XposedBridge.log(TAG + ": Hooking Alipay NFC detection");

        hookHasSystemFeature();
        hookNfcAdapter();
        hookNfcManager();
    }

    private void hookHasSystemFeature() {
        try {
            Class<?> appPmClass = XposedHelpers.findClass(
                "android.app.ApplicationPackageManager", null
            );

            // PackageManager.hasSystemFeature(String)
            XposedHelpers.findAndHookMethod(appPmClass, "hasSystemFeature",
                String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String feature = (String) param.args[0];
                        if (isNfcFeature(feature)) {
                            Log.i(TAG, "Blocked hasSystemFeature(" + feature + ")");
                            XposedBridge.log(TAG + ": Blocked hasSystemFeature(" + feature + ")");
                            param.setResult(false);
                        }
                    }
                });

            // PackageManager.hasSystemFeature(String, int)
            XposedHelpers.findAndHookMethod(appPmClass, "hasSystemFeature",
                String.class, int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String feature = (String) param.args[0];
                        if (isNfcFeature(feature)) {
                            Log.i(TAG, "Blocked hasSystemFeature(" + feature + ", ver)");
                            param.setResult(false);
                        }
                    }
                });

            XposedBridge.log(TAG + ": hooked ApplicationPackageManager");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook ApplicationPackageManager: " + t);
        }
    }

    private void hookNfcAdapter() {
        try {
            // NfcAdapter.getDefaultAdapter(Context)
            XposedHelpers.findAndHookMethod(NfcAdapter.class, "getDefaultAdapter",
                Context.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Log.i(TAG, "Blocked NfcAdapter.getDefaultAdapter(Context)");
                        param.setResult(null);
                    }
                });
            XposedBridge.log(TAG + ": hooked NfcAdapter.getDefaultAdapter(Context)");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook NfcAdapter.getDefaultAdapter: " + t);
        }

        try {
            // NfcAdapter.getDefaultAdapter() — exists on some Android versions
            XposedHelpers.findAndHookMethod(NfcAdapter.class, "getDefaultAdapter",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Log.i(TAG, "Blocked NfcAdapter.getDefaultAdapter()");
                        param.setResult(null);
                    }
                });
            XposedBridge.log(TAG + ": hooked NfcAdapter.getDefaultAdapter()");
        } catch (Throwable t) {
            // no-op: this overload may not exist on this Android version
        }
    }

    private void hookNfcManager() {
        try {
            // NfcManager.getDefaultAdapter()
            XposedHelpers.findAndHookMethod(NfcManager.class, "getDefaultAdapter",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Log.i(TAG, "Blocked NfcManager.getDefaultAdapter()");
                        param.setResult(null);
                    }
                });
            XposedBridge.log(TAG + ": hooked NfcManager.getDefaultAdapter()");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook NfcManager: " + t);
        }
    }

    private boolean isNfcFeature(String feature) {
        if (feature == null) return false;
        for (String nfc : NFC_FEATURES) {
            if (nfc.equals(feature)) return true;
        }
        return false;
    }
}
