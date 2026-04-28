package dev.merosssany.bluewall;

import dev.merosssany.bluewall.policy.ClassAccessPolicy;
import dev.merosssany.bluewall.policy.FieldAccessPolicy;
import dev.merosssany.bluewall.policy.MethodAccessPolicy;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class AccessPolicyBuilder {
    protected MethodAccessPolicy method;
    protected ClassAccessPolicy clazz;
    protected FieldAccessPolicy field;
    
    public AccessPolicyBuilder(MethodAccessPolicy method, ClassAccessPolicy clazz, FieldAccessPolicy field) {
        this.method = method;
        this.clazz = clazz;
        this.field = field;
    }
    
    public AccessPolicyBuilder(SecurityKey key) {
        method = new MethodAccessPolicy(key);
        clazz = new ClassAccessPolicy(key);
        field = new FieldAccessPolicy(key);
    }
    
    public AccessPolicyBuilder allow(SecurityKey key, Class<?> cls) {
        clazz.allow(key, cls);
        return this;
    }
    
    public AccessPolicyBuilder allow(SecurityKey key, Method method) {
        this.method.allow(key, method);
        return this;
    }
    
    public AccessPolicyBuilder allow(SecurityKey key, Field field) {
        this.field.allow(key, field);
        return this;
    }
    
    public AccessPolicyBuilder deny(SecurityKey key, Class<?> cls) {
        clazz.deny(key, cls);
        return this;
    }
    
    public AccessPolicyBuilder deny(SecurityKey key, Method method) {
        this.method.deny(key, method);
        return this;
    }
    
    public AccessPolicyBuilder deny(SecurityKey key, Field field) {
        this.field.deny(key, field);
        return this;
    }
    
    public AccessPolicyBuilder setMethodAccessMode(SecurityKey key, AccessMode mode) {
        method.setMode(key, mode);
        return this;
    }
    
    public AccessPolicyBuilder setClassAccessMode(SecurityKey key, AccessMode mode) {
        clazz.setMode(key, mode);
        return this;
    }
    
    public AccessPolicyBuilder setFieldAccessMode(SecurityKey key, AccessMode mode) {
        field.setMode(key, mode);
        return this;
    }
    
    public AccessPolicyBuilder removeAllowedMethod(SecurityKey key, Method allowed) {
        method.removeAllowedMethod(key, allowed);
        return this;
    }
    
    public AccessPolicyBuilder removeDeniedMethod(SecurityKey key, Method denied) {
        method.removeDeniedMethod(key, denied);
        return this;
    }
    
    public AccessPolicyBuilder removeAllowedField(SecurityKey key, Field allowed) {
        field.removeAllowedField(key, allowed);
        return this;
    }
    
    public AccessPolicyBuilder removeDeniedField(SecurityKey key, Field denied) {
        field.removeDeniedField(key, denied);
        return this;
    }
    
    public AccessPolicyBuilder allow(SecurityKey key, MethodAccessPolicy.AccessMethod method) {
        this.method.allow(key, method);
        return this;
    }
    
    public AccessPolicyBuilder deny(SecurityKey key, MethodAccessPolicy.AccessMethod method) {
        this.method.deny(key, method);
        return this;
    }
    
    public AccessPolicyBuilder allow(SecurityKey key, String cls) {
        clazz.allow(key, cls);
        return this;
    }
    
    public AccessPolicyBuilder deny(SecurityKey key, String cls) {
        clazz.deny(key, cls);
        return this;
    
    }
    public AccessPolicyBuilder allow(SecurityKey key, FieldAccessPolicy.AccessField method) {
        field.allow(key, method);
        return this;
    }
    
    public AccessPolicyBuilder deny(SecurityKey key, FieldAccessPolicy.AccessField method) {
        field.deny(key, method);
        return this;
    }
    
    public AccessPolicyBuilder removeAllowedMethod(SecurityKey key, MethodAccessPolicy.AccessMethod allowed) {
        method.removeAllowedMethod(key, allowed);
        return this;
    }
    
    public AccessPolicyBuilder removeDeniedMethod(SecurityKey key, MethodAccessPolicy.AccessMethod denied) {
        method.removeDeniedMethod(key, denied);
        return this;
    }
    
    public AccessPolicyBuilder removeAllowedField(SecurityKey key, FieldAccessPolicy.AccessField allowed) {
        field.removeAllowedField(key, allowed);
        return this;
    }
    
    public AccessPolicyBuilder removeDeniedField(SecurityKey key, FieldAccessPolicy.AccessField denied) {
        field.removeDeniedField(key, denied);
        return this;
    }
    
    public AccessPolicyBuilder removeAllowedClass(SecurityKey key, String allowed) {
        clazz.removeAllowedClass(key, allowed);
        return this;
    }
    
    public AccessPolicyBuilder removeDeniedClass(SecurityKey key, String denied) {
        clazz.removeDeniedClass(key, denied);
        return this;
    }
    
    public AccessPolicyBuilder clearMethodWhitelist(SecurityKey key) {
        method.clearWhitelist(key);
        return this;
    }
    
    public AccessPolicyBuilder clearMethodBlacklist(SecurityKey key) {
        method.clearBlacklist(key);
        return this;
    }
    
    public AccessPolicyBuilder clearClassWhitelist(SecurityKey key) {
        clazz.clearWhitelist(key);
        return this;
    }
    
    public AccessPolicyBuilder clearClassBlacklist(SecurityKey key) {
        clazz.clearBlacklist(key);
        return this;
    }
    
    public AccessPolicyBuilder clearFieldWhitelist(SecurityKey key) {
        field.clearWhitelist(key);
        return this;
    }
    
    public AccessPolicyBuilder clearFieldBlacklist(SecurityKey key) {
        field.clearBlacklist(key);
        return this;
    }
    
    public AccessPolicyBuilder clearBlacklist(SecurityKey key) {
        return clearFieldBlacklist(key).clearClassBlacklist(key).clearMethodBlacklist(key);
    }
    
    public AccessPolicyBuilder clearWhitelist(SecurityKey key) {
        return clearFieldWhitelist(key).clearClassWhitelist(key).clearMethodWhitelist(key);
    }
    
    public MethodAccessPolicy getMethodAccessPolicy() {
        return method;
    }
    
    public ClassAccessPolicy getClassAccessPolicy() {
        return clazz;
    }
    
    public FieldAccessPolicy getFieldAccessPolicy() {
        return field;
    }
    
    public AccessPolicyBuilder allow(SecurityKey key, Package pkg) {
        clazz.allow(key, pkg);
        return this;
    }
    
    public AccessPolicyBuilder deny(SecurityKey key, Package pkg) {
        clazz.deny(key, pkg);
        return this;
    }
    
    public SandboxedClassLoader build() {
        return new SandboxedClassLoader(clazz, method, field);
    }
}
