package dev.merosssany.bluewall.template;

import dev.merosssany.bluewall.AccessPolicyBuilder;
import dev.merosssany.bluewall.ClassHelper;
import dev.merosssany.bluewall.SecurityKey;

import java.lang.reflect.Field;

public class DefaultJavaAccessPolicy {
    public static void apply(SecurityKey key, AccessPolicyBuilder policy) {
        try {
            policy.allow(key, String.class.getPackage())        // java.lang
                    .deny(key, Runtime.class)
                    .deny(key, ProcessBuilder.class)
                    .deny(key, Thread.class)
                    .deny(key, ClassLoader.class)
                    .deny(key, Field.class.getPackage())       // java.lang.reflect
                    .deny(key, ClassHelper.getMethod(System.class, "exit", new Class<?>[]{int.class}))
                    .deny(key, ClassHelper.getMethod(System.class, "loadLibrary", new Class<?>[]{}))
                    .deny(key, ClassHelper.getMethod(System.class, "getenv", new Class<?>[]{}))
                    .deny(key, "sun/misc");                  // Unsafe etc.
        } catch (NoSuchMethodException e) {
            e.printStackTrace(); // shouldn't happen
        }
    }
}
