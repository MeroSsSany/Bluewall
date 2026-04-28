package dev.merosssany.bluewall.policy;

import dev.merosssany.bluewall.AccessMode;
import dev.merosssany.bluewall.ClassIdentifier;
import dev.merosssany.bluewall.SecurityKey;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class MethodAccessPolicy {
    private final Set<AccessMethod> whitelist = ConcurrentHashMap.newKeySet();
    private final Set<AccessMethod> blacklist = ConcurrentHashMap.newKeySet();
    private final SecurityKey key;
    private AccessMode mode;
    
    public MethodAccessPolicy(SecurityKey key) {
        this.key = key;
    }
    
    public AccessMode getMode() {
        return mode;
    }
    
    public void setMode(SecurityKey key, AccessMode mode) {
        if (this.key == key) this.mode = mode;
        else throw new SecurityException("Incorrect key");
    }
    
    public boolean isAllowed(AccessMethod method) {
        if (blacklist.isEmpty() && whitelist.isEmpty()) return true; // disabled
        if (blacklist.contains(method)) return false;
        
        if (mode == AccessMode.WHITELIST) {
            return whitelist.contains(method);
        } else {
            return true;
        }
    }
    
    public boolean isAllowed(Method method) {
        return isAllowed(new AccessMethod(method));
    }
    
    public void allow(SecurityKey key, AccessMethod method) {
        if (this.key == key) whitelist.add(method);
        else throw new SecurityException("Incorrect key");
    }
    
    public void allow(SecurityKey key, Method method) {
        allow(key, new AccessMethod(method));
    }
    
    public void deny(SecurityKey key, AccessMethod method) {
        if (this.key == key) blacklist.add(method);
        else throw new SecurityException("Incorrect key");
    }
    
    public void deny(SecurityKey key, Method method) {
        deny(key, new AccessMethod(method));
    }
    
    public void removeAllowedClass(SecurityKey key, AccessMethod allowed) {
        if (this.key == key) whitelist.remove(allowed);
        else throw new SecurityException("Incorrect key");
    }
    
    public void removeAllowedClass(SecurityKey key, Method allowed) {
        removeAllowedClass(key, new AccessMethod(allowed));
    }
    
    public void removeDeniedClass(SecurityKey key, AccessMethod denied) {
        if (this.key == key) blacklist.remove(denied);
        else throw new SecurityException("Incorrect key");
    }
    
    public void removeDeniedClass(SecurityKey key, Method denied) {
        removeDeniedClass(key, new AccessMethod(denied));
    }
    
    public void clearWhitelist(SecurityKey key) {
        if (this.key == key) whitelist.clear();
        else throw new SecurityException("Incorrect key");
    }
    
    public void clearBlacklist(SecurityKey key) {
        if (this.key == key) blacklist.clear();
        else throw new SecurityException("Incorrect key");
    }
    
    public record AccessMethod(
            String cls,
            String name,
            String descriptor
    ) {
        public AccessMethod(Method method) {
            this(
                    ClassIdentifier.toInternalName(method.getDeclaringClass()),
                    method.getName(),
                    ClassIdentifier.toDescriptor(method)
            );
        }
    }
}
