# UniFFI bindings use JNA, which finds classes and fields by reflection.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-keep class uniffi.vault_mobile.** { *; }
-dontwarn java.awt.**
