package dev.merosssany.bluewall;

import java.lang.reflect.Method;

public class ClassIdentifier {
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
    
    public static boolean isPrimitive(Class<?> cls) {
        if (cls.isPrimitive()) return true;
        else if (Number.class.isAssignableFrom(cls)) return true;
        else return Character.class.isAssignableFrom(cls);
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
            default -> descriptor;
        };
    }
    
    public static String toInternalName(String name) {
        return name.replace('.','/');
    }
}
