# Keep UniFFI generated code
-keep class io.privkey.keep.uniffi.** { *; }

# Keep JNA classes
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}
