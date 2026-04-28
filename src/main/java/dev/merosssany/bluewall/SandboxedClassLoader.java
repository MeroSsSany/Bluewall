package dev.merosssany.bluewall;

import dev.merosssany.bluewall.policy.ClassAccessPolicy;
import dev.merosssany.bluewall.policy.FieldAccessPolicy;
import dev.merosssany.bluewall.policy.MethodAccessPolicy;
import org.objectweb.asm.*;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;

public class SandboxedClassLoader extends ClassLoader {
    private final ClassAccessPolicy classPolicy;
    private final MethodAccessPolicy methodPolicy;
    private final FieldAccessPolicy fieldPolicy;
    
    public SandboxedClassLoader(ClassAccessPolicy classPolicy, MethodAccessPolicy methodPolicy, FieldAccessPolicy fieldPolicy) {
        this.classPolicy = classPolicy;
        this.methodPolicy = methodPolicy;
        this.fieldPolicy = fieldPolicy;
    }
    
    public Class<?> defineClassSandboxed(String name, byte[] b) {
        ClassReader cr = new ClassReader(b);
        cr.accept(getClassVisitor(), ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return defineClass(name, b, 0, b.length);
    }
    
    private ClassVisitor getClassVisitor() {
        return new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visit(int version, int access, String name, String signature,
                              String superName, String[] interfaces) {
                
                if (!classPolicy.isAllowed(superName)) {
                    throw new SecurityException("Forbidden superclass: " + superName);
                }
                
                if (!classPolicy.isAllowed(name)) {
                    throw new SecurityException("Forbidden class name: " + name);
                }
                
                if (interfaces != null) {
                    for (String iface : interfaces) {
                        if (!classPolicy.isAllowed(iface)) {
                            throw new SecurityException("Forbidden interface: " + iface);
                        }
                    }
                }
                
                if (signature != null) {
                    new SignatureReader(signature).accept(new SignatureVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitClassType(String name) {
                            if (!classPolicy.isAllowed(name)) {
                                throw new SecurityException("Forbidden class signature type: " + name);
                            }
                        }
                    });
                }
                
                super.visit(version, access, name, signature, superName, interfaces);
            }
            
            @Override
            public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
                Type t = Type.getType(descriptor);
                Type element = getType(t);
                
                if (element.getSort() == Type.OBJECT &&
                        !classPolicy.isAllowed(element.getInternalName())) {
                    throw new SecurityException("Forbidden field type: " + descriptor);
                }
                
                if (signature != null) {
                    new SignatureReader(signature).accept(new SignatureVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitClassType(String name) {
                            if (!classPolicy.isAllowed(name)) {
                                throw new SecurityException("Forbidden field signature type: " + name);
                            }
                        }
                    });
                }
                
                return super.visitField(access, name, descriptor, signature, value);
            }
            
            @Override
            public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
                return new AnnotationVisitor(Opcodes.ASM9, super.visitAnnotation(desc, visible)) {
                    @Override
                    public void visit(String name, Object value) {
                        if (value instanceof Type t) {
                            if (t.getSort() == Type.OBJECT &&
                                    !classPolicy.isAllowed(t.getInternalName())) {
                                throw new SecurityException("Forbidden annotation value type: " + t);
                            }
                        }
                        super.visit(name, value);
                    }
                };
            }
            
            @Override
            public MethodVisitor visitMethod(int access, String methodName, String descriptor, String signature, String[] exceptions) {
                Type methodType = Type.getMethodType(descriptor);
                
                for (Type arg : methodType.getArgumentTypes()) {
                    if (arg.getSort() == Type.OBJECT || arg.getSort() == Type.ARRAY) {
                        Type element = getType(arg);
                        
                        if (element.getSort() == Type.OBJECT &&
                                !classPolicy.isAllowed(element.getInternalName())) {
                            throw new SecurityException("Forbidden parameter type: " + arg);
                        }
                    }
                }
                
                Type ret = methodType.getReturnType();
                if (ret.getSort() == Type.OBJECT || ret.getSort() == Type.ARRAY) {
                    Type element = getType(ret);
                    
                    if (element.getSort() == Type.OBJECT &&
                            !classPolicy.isAllowed(element.getInternalName())) {
                        throw new SecurityException("Forbidden return type: " + ret);
                    }
                }
                
                if (exceptions != null) {
                    for (String ex : exceptions) {
                        if (!classPolicy.isAllowed(ex)) {
                            throw new SecurityException("Forbidden exception type: " + ex);
                        }
                    }
                }
                
                if (signature != null) {
                    new SignatureReader(signature).accept(new SignatureVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitClassType(String name) {
                            if (!classPolicy.isAllowed(name)) {
                                throw new SecurityException("Forbidden signature type: " + name);
                            }
                        }
                    });
                }
                
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                        if (!classPolicy.isAllowed(owner) ||
                                !methodPolicy.isAllowed(new MethodAccessPolicy.AccessMethod(owner, name, descriptor))) {
                            throw new SecurityException("Forbidden method call: " + owner + "." + name);
                        }
                        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                    }
                    
                    @Override
                    public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
                        String internalName = ClassHelper.toInternalNameFromDescriptor(descriptor);
                        if (
                                !classPolicy.isAllowed(owner) ||
                                !fieldPolicy.isAllowed(new FieldAccessPolicy.AccessField(owner, name)) || (
                                internalName != null &&
                                !classPolicy.isAllowed(internalName))
                        ) {
                            throw new SecurityException("Forbidden field access: " + owner + "." + name);
                        }
                        super.visitFieldInsn(opcode, owner, name, descriptor);
                    }
                    
                    @Override
                    public void visitTypeInsn(int opcode, String type) {
                        Type t = Type.getObjectType(type);
                        
                        if (t.getSort() == Type.ARRAY) {
                            Type element = getType(t);
                            if (element.getSort() == Type.OBJECT &&
                                    !classPolicy.isAllowed(element.getInternalName())) {
                                    throw new SecurityException("Forbidden array type: " + type);
                                }
                            
                        } else {
                            if (!classPolicy.isAllowed(type)) {
                                throw new SecurityException("Forbidden type: " + type);
                            }
                        }
                        
                        super.visitTypeInsn(opcode, type);
                    }
                    
                    @Override
                    public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
                        return getAnnotationVisitor(desc, visible);
                    }
                    
                    @Override
                    public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
                        return getAnnotationVisitor(desc, visible);
                    }
                    
                    @Override
                    public AnnotationVisitor visitParameterAnnotation(int parameter, String desc, boolean visible) {
                        return getAnnotationVisitor(desc, visible);
                    }
                    
                    private AnnotationVisitor getAnnotationVisitor(String desc, boolean visible) {
                        return new AnnotationVisitor(Opcodes.ASM9, super.visitAnnotation(desc, visible)) {
                            @Override
                            public void visit(String name, Object value) {
                                if (value instanceof Type t) {
                                    if (t.getSort() == Type.OBJECT &&
                                            !classPolicy.isAllowed(t.getInternalName())) {
                                        throw new SecurityException("Forbidden annotation value type: " + t);
                                    }
                                }
                                super.visit(name, value);
                            }
                        };
                    }
                    
                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof Handle h) {
                            if (!classPolicy.isAllowed(h.getOwner()) ||
                                    !methodPolicy.isAllowed(new MethodAccessPolicy.AccessMethod(
                                            h.getOwner(), h.getName(), h.getDesc()))) {
                                throw new SecurityException("Forbidden handle: " + h.getOwner() + "." + h.getName());
                            }
                        }
                        
                        if (value instanceof Type t) {
                            if (t.getSort() == Type.OBJECT) {
                                if (!classPolicy.isAllowed(t.getInternalName())) {
                                    throw new SecurityException("Forbidden class literal: " + t.getInternalName());
                                }
                            } else if (t.getSort() == Type.METHOD) {
                                for (Type arg : t.getArgumentTypes()) {
                                    if (arg.getSort() == Type.OBJECT ||
                                            arg.getSort() == Type.ARRAY) {
                                        
                                        Type element = getType(arg);
                                        
                                        if (element.getSort() == Type.OBJECT &&
                                                !classPolicy.isAllowed(element.getInternalName())) {
                                            throw new SecurityException("Forbidden parameter type: " + arg);
                                        }
                                    }
                                }
                                
                                Type ret = t.getReturnType();
                                if (ret.getSort() == Type.OBJECT ||
                                        ret.getSort() == Type.ARRAY) {
                                    
                                    Type element = getType(ret);
                                    
                                    if (element.getSort() == Type.OBJECT &&
                                            !classPolicy.isAllowed(element.getInternalName())) {
                                        throw new SecurityException("Forbidden return type: " + ret);
                                    }
                                }
                            }
                        }
                        
                        if (value instanceof ConstantDynamic cd) {
                            Handle bsm = cd.getBootstrapMethod();
                            
                            if (!classPolicy.isAllowed(bsm.getOwner()) ||
                                    !methodPolicy.isAllowed(new MethodAccessPolicy.AccessMethod(
                                            bsm.getOwner(), bsm.getName(), bsm.getDesc()))) {
                                throw new SecurityException("Forbidden condy bootstrap: " + bsm.getOwner());
                            }
                            
                            for (int i = 0; i < cd.getBootstrapMethodArgumentCount(); i++) {
                                Object arg = cd.getBootstrapMethodArgument(i);
                                
                                if (arg instanceof Handle h) {
                                    if (!classPolicy.isAllowed(h.getOwner()) ||
                                            !methodPolicy.isAllowed(new MethodAccessPolicy.AccessMethod(
                                                    h.getOwner(), h.getName(), h.getDesc()))) {
                                        throw new SecurityException("Forbidden condy handle: " + h.getOwner());
                                    }
                                }
                                
                                if (arg instanceof Type t) {
                                    Type base = getType(t);
                                    if (base.getSort() == Type.OBJECT &&
                                            !classPolicy.isAllowed(base.getInternalName())) {
                                        throw new SecurityException("Forbidden condy type: " + t);
                                    }
                                }
                            }
                        }
                        
                        super.visitLdcInsn(value);
                    }
                    
                    @Override
                    public void visitInvokeDynamicInsn(String name, String descriptor, Handle bsm, Object... bsmArgs) {
                        if (!classPolicy.isAllowed(bsm.getOwner()) ||
                                !methodPolicy.isAllowed(new MethodAccessPolicy.AccessMethod(
                                        bsm.getOwner(), bsm.getName(), bsm.getDesc()))) {
                            throw new SecurityException("Forbidden bootstrap: " + bsm.getOwner() + "." + bsm.getName());
                        }
                        
                        Type indyType = Type.getMethodType(descriptor);

                        for (Type arg : indyType.getArgumentTypes()) {
                            if (arg.getSort() == Type.OBJECT || arg.getSort() == Type.ARRAY) {
                                Type element = getType(arg);
                                
                                if (element.getSort() == Type.OBJECT &&
                                        !classPolicy.isAllowed(element.getInternalName())) {
                                    throw new SecurityException("Forbidden indy parameter type: " + arg);
                                }
                            }
                        }

                        Type ret = indyType.getReturnType();
                        if (ret.getSort() == Type.OBJECT || ret.getSort() == Type.ARRAY) {
                            Type element = getType(ret);
                            
                            if (element.getSort() == Type.OBJECT &&
                                    !classPolicy.isAllowed(element.getInternalName())) {
                                throw new SecurityException("Forbidden indy return type: " + ret);
                            }
                        }
                        
                        for (Object arg : bsmArgs) {
                            if (arg instanceof Handle h) {
                                if (!classPolicy.isAllowed(h.getOwner()) ||
                                        !methodPolicy.isAllowed(new MethodAccessPolicy.AccessMethod(
                                                h.getOwner(), h.getName(), h.getDesc()))) {
                                    throw new SecurityException("Forbidden indy arg handle: " + h.getOwner());
                                }
                            }
                            
                            if (arg instanceof Type t) {
                                if (t.getSort() == Type.OBJECT || t.getSort() == Type.ARRAY) {
                                    Type element = getType(t);
                                    
                                    if (element.getSort() == Type.OBJECT &&
                                            !classPolicy.isAllowed(element.getInternalName())) {
                                        throw new SecurityException("Forbidden indy arg type: " + t);
                                    }
                                }
                            }
                        }
                        
                        super.visitInvokeDynamicInsn(name, descriptor, bsm, bsmArgs);
                    }
                    
                    @Override
                    public void visitMultiANewArrayInsn(String descriptor, int numDimensions) {
                        String internalName = ClassHelper.toInternalNameFromDescriptor(descriptor);
                        
                        if (internalName != null) {
                            if (!classPolicy.isAllowed(internalName)) throw new SecurityException("Forbidden multiarray type: "+internalName);
                        }
                        
                        super.visitMultiANewArrayInsn(descriptor, numDimensions);
                    }
                    
                    @Override
                    public void visitInsn(int opcode) {
                        if (opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
                            throw new SecurityException("Threading/Synchronization is forbidden.");
                        }
                        super.visitInsn(opcode);
                    }
                };
            }
        };
    }
    
    private static Type getType(Type ret) {
        Type element = ret;
        while (element.getSort() == Type.ARRAY) {
            element = element.getElementType();
        }
        return element;
    }
}
