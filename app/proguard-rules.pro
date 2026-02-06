# Suppress warnings for missing classes (not needed at runtime on Android)
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn java.awt.**

# ZXing QR code generation
-keep class com.google.zxing.qrcode.QRCodeWriter { *; }
-keep class com.google.zxing.BarcodeFormat { *; }
-keep class com.google.zxing.EncodeHintType { *; }
-keep class com.google.zxing.qrcode.decoder.ErrorCorrectionLevel { *; }
-keep class com.google.zxing.common.BitMatrix { *; }

# Keep UniFFI generated code
-keep class io.privkey.keep.uniffi.** { *; }

# Keep JNA classes
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# SQLCipher
-keep class net.zetetic.database.** { *; }
