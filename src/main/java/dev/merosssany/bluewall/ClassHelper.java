package dev.merosssany.bluewall;

import java.lang.reflect.Method;
import java.util.Set;

public class ClassHelper {
    public static String toInternalName(Class<?> cls) {
        return cls.getName().replace(".","/");
    }
    
    public static String toDescriptor(Method method) {
        StringBuilder paramList = new StringBuilder();
        
        for (Class<?> param : method.getParameterTypes()) {
            paramList.append(param.descriptorString());
        }
        
        return "(" + paramList + ")" + method.getReturnType().descriptorString();
    }
    
    public static String toDescriptor(Class<?> cls) {
        return cls.descriptorString();
    }
    
    private static final Set<Class<?>> WRAPPERS = Set.of(
            Integer.class, Long.class, Boolean.class, Double.class,
            Float.class, Character.class, Byte.class, Short.class
    );
    
    public static boolean isPrimitive(Class<?> cls) {
        return cls.isPrimitive() || WRAPPERS.contains(cls);
    }
    
    public static String boxingOf(String descriptor) {
        return switch (descriptor) {
            case "I" -> "Ljava/lang/Integer;";
            case "J"   -> "Ljava/lang/Long;";
            case "Z" -> "Ljava/lang/Boolean;";
            case "D" -> "Ljava/lang/Double;";
            case "F" -> "Ljava/lang/Float;";
            case "C" -> "Ljava/lang/Character;";
            case "B" -> "Ljava/lang/Byte;";
            case "S" -> "Ljava/lang/Short;";
            default -> descriptor;
        };
    }
    
    public static String unboxingOf(String descriptor) {
        return switch (descriptor) {
            case "Ljava/lang/Integer;" -> "I";
            case "Ljava/lang/Long;"    -> "J";
            case "Ljava/lang/Boolean;" -> "Z";
            case "Ljava/lang/Double;"  -> "D";
            case "Ljava/lang/Float;"   -> "F";
            case "Ljava/lang/Character;" -> "C";
            case "Ljava/lang/Byte;" -> "B";
            case "Ljava/lang/Short;" -> "S";
            default -> descriptor;
        };
    }
    
    public static String toInternalName(String name) {
        return name.replace('.','/');
    }
    
    public static Method getMethod(Class<?> cls, String method, Class<?>[] params) throws NoSuchMethodException {
        return cls.getMethod(method, params);
    }
}
