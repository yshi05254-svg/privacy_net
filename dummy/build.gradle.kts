plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.privacygate.dummy"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.privacygate.dummy"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }
}
