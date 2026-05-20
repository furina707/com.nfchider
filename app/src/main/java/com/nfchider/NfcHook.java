package com.nfchider;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.util.Log;

import androidx.annotation.NonNull;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class NfcHook extends XposedModule {

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
    public void onPackageLoaded(@NonNull PackageLoadedParam param) {
        if (!TARGET_PKG.equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "Hooking Alipay NFC detection");
        hookHasSystemFeature(param);
        hookNfcAdapter();
        hookNfcManager();
    }

    private void hookHasSystemFeature(PackageLoadedParam param) {
        try {
            Class<?> appPmClass = param.getDefaultClassLoader().loadClass("android.app.ApplicationPackageManager");

            Method hasFeature1 = appPmClass.getMethod("hasSystemFeature", String.class);
            hook(hasFeature1).intercept(chain -> {
                String feature = (String) chain.getArg(0);
                if (isNfcFeature(feature)) {
                    log(Log.INFO, TAG, "Blocked hasSystemFeature(" + feature + ")");
                    return false;
                }
                return chain.proceed();
            });

            Method hasFeature2 = appPmClass.getMethod("hasSystemFeature", String.class, int.class);
            hook(hasFeature2).intercept(chain -> {
                String feature = (String) chain.getArg(0);
                if (isNfcFeature(feature)) {
                    log(Log.INFO, TAG, "Blocked hasSystemFeature(" + feature + ", ver)");
                    return false;
                }
                return chain.proceed();
            });

            log(Log.INFO, TAG, "hooked ApplicationPackageManager");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook ApplicationPackageManager: " + t);
        }
    }

    private void hookNfcAdapter() {
        try {
            Method getDefaultAdapter1 = NfcAdapter.class.getMethod("getDefaultAdapter", Context.class);
            hook(getDefaultAdapter1).intercept(chain -> {
                log(Log.INFO, TAG, "Blocked NfcAdapter.getDefaultAdapter(Context)");
                return null;
            });
            log(Log.INFO, TAG, "hooked NfcAdapter.getDefaultAdapter(Context)");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook NfcAdapter.getDefaultAdapter(Context): " + t);
        }

        try {
            Method getDefaultAdapter2 = NfcAdapter.class.getMethod("getDefaultAdapter");
            hook(getDefaultAdapter2).intercept(chain -> {
                log(Log.INFO, TAG, "Blocked NfcAdapter.getDefaultAdapter()");
                return null;
            });
            log(Log.INFO, TAG, "hooked NfcAdapter.getDefaultAdapter()");
        } catch (Throwable t) {
        }
    }

    private void hookNfcManager() {
        try {
            Method nfcGetDefaultAdapter = NfcManager.class.getMethod("getDefaultAdapter");
            hook(nfcGetDefaultAdapter).intercept(chain -> {
                log(Log.INFO, TAG, "Blocked NfcManager.getDefaultAdapter()");
                return null;
            });
            log(Log.INFO, TAG, "hooked NfcManager.getDefaultAdapter()");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to hook NfcManager: " + t);
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