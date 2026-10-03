plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.privacygate"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.privacygate"
        minSdk = 34
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
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
    // libxposed API 101（Maven Central 与设备上 Vector v2.2 同源；PLAN §2 原计划从 Vector 源码拷贝，
    // 本机无该源码路径，改为拷贝发布物到 libs/，偏差记入 README）
    compileOnly(files("../libs/libxposed/api-101.0.1-classes.jar"))

    testImplementation("junit:junit:4.13.2")
    // JVM 单测用真实 org.json 实现（运行时用 Android 平台自带的同名 API）
    testImplementation("org.json:json:20240303")
}
