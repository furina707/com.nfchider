package io.github.libxposed.api;

import android.app.AppComponentFactory;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

@SuppressWarnings("unused")
public interface XposedModuleInterface {
    interface ModuleLoadedParam {
        boolean isSystemServer();

        @NonNull
        String getProcessName();
    }

    interface PackageLoadedParam {
        @NonNull
        String getPackageName();

        @NonNull
        ApplicationInfo getApplicationInfo();

        boolean isFirstPackage();

        @RequiresApi(Build.VERSION_CODES.Q)
        @NonNull
        ClassLoader getDefaultClassLoader();
    }

    interface PackageReadyParam extends PackageLoadedParam {
        @NonNull
        ClassLoader getClassLoader();

        @RequiresApi(Build.VERSION_CODES.P)
        @NonNull
        AppComponentFactory getAppComponentFactory();
    }

    interface SystemServerStartingParam {
        @NonNull
        ClassLoader getClassLoader();
    }

    default void onModuleLoaded(@NonNull ModuleLoadedParam param) {
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    default void onPackageLoaded(@NonNull PackageLoadedParam param) {
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    default void onPackageReady(@NonNull PackageReadyParam param) {
    }

    default void onSystemServerStarting(@NonNull SystemServerStartingParam param) {
    }
}