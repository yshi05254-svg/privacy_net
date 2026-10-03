plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.privacygate.detector"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.privacygate.detector"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    flavorDimensions += "mode"
    productFlavors {
        // 声明 QUERY_ALL_PACKAGES：模拟"持有全量查询权限"的第三方 app
        create("full") {
            dimension = "mode"
            applicationIdSuffix = ".full"
        }
        // 只带 <queries> 白名单：模拟拼多多/微信类的"受限可见"第三方 app（复现原生泄露）
        create("queries") {
            dimension = "mode"
            applicationIdSuffix = ".queries"
        }
    }

    buildFeatures {
        buildConfig = true
        aidl = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
}
