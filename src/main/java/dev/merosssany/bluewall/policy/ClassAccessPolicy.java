package dev.merosssany.bluewall.policy;

import dev.merosssany.bluewall.AccessMode;
import dev.merosssany.bluewall.ClassIdentifier;
import dev.merosssany.bluewall.SecurityKey;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class ClassAccessPolicy {
    private final Set<String> whitelist = ConcurrentHashMap.newKeySet();
    private final Set<String> blacklist = ConcurrentHashMap.newKeySet();
    private final SecurityKey key;
    private AccessMode mode;
    
    public ClassAccessPolicy(SecurityKey key) {
        this.key = key;
    }
    
    public AccessMode getMode() {
        return mode;
    }
    
    public void setMode(SecurityKey key, AccessMode mode) {
        if (this.key == key) this.mode = mode;
        else throw new SecurityException("Incorrect key");
    }
    
    public boolean isAllowed(String cls) {
        if (blacklist.stream().anyMatch(cls::startsWith)) return false;
        
        if (mode == AccessMode.WHITELIST) {
            // Check if the specific class OR its parent package is whitelisted
            return whitelist.stream().anyMatch(cls::startsWith);
        }
        return true;
    }
    
    public boolean isAllowed(Class<?> cls) {
        return isAllowed(ClassIdentifier.toInternalName(cls));
    }
    
    public void allow(SecurityKey key, String cls) {
        if (this.key == key) whitelist.add(cls);
        else throw new SecurityException("Incorrect key");
    }
    
    public void allow(SecurityKey key, Class<?> cls) {
        allow(key, ClassIdentifier.toInternalName(cls));
    }
    
    public void deny(SecurityKey key, String cls) {
        if (this.key == key) blacklist.add(cls);
        else throw new SecurityException("Incorrect key");
    }
    
    public void deny(SecurityKey key, Class<?> cls) {
        deny(key, ClassIdentifier.toInternalName(cls));
    }
    
    public void removeAllowedClass(SecurityKey key, String allowed) {
        if (this.key == key) whitelist.remove(allowed);
        else throw new SecurityException("Incorrect key");
    }
    
    public void removeAllowedClass(SecurityKey key, Class<?> allowed) {
        removeAllowedClass(key, ClassIdentifier.toInternalName(allowed));
    }
    
    public void removeDeniedClass(SecurityKey key, String denied) {
        if (this.key == key) blacklist.remove(denied);
        else throw new SecurityException("Incorrect key");
    }
    
    public void removeDeniedClass(SecurityKey key, Class<?> denied) {
        removeDeniedClass(key, ClassIdentifier.toInternalName(denied));
    }
}
