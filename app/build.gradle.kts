plugins {
    id("com.android.application")
}

android {
    namespace = "com.nfchider"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.nfchider"
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        val keystorePath = System.getenv("KEYSTORE_PATH")
        if (!keystorePath.isNullOrBlank()) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("KEYSTORE_PASSWORD") ?: ""
                keyAlias = System.getenv("KEY_ALIAS") ?: ""
                keyPassword = System.getenv("KEY_PASSWORD") ?: ""
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfigs.findByName("release")?.let {
                signingConfig = it
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    compileOnly("io.github.libxposed:api:101.0.1")
    compileOnly("androidx.annotation:annotation:1.9.1")
}
