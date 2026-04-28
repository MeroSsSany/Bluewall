package dev.merosssany.bluewall.policy;

import dev.merosssany.bluewall.AccessMode;
import dev.merosssany.bluewall.ClassIdentifier;
import dev.merosssany.bluewall.SecurityKey;

import java.lang.reflect.Field;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class FieldAccessPolicy {
    private final Set<AccessField> whitelist = ConcurrentHashMap.newKeySet();
    private final Set<AccessField> blacklist = ConcurrentHashMap.newKeySet();
    private final SecurityKey key;
    private AccessMode mode;
    
    public FieldAccessPolicy(SecurityKey key) {
        this.key = key;
    }
    
    public AccessMode getMode() {
        return mode;
    }
    
    public void setMode(SecurityKey key, AccessMode mode) {
        if (this.key == key) this.mode = mode;
        else throw new SecurityException("Incorrect key");
    }
    
    public boolean isAllowed(AccessField method) {
        if (blacklist.isEmpty() && whitelist.isEmpty()) return true; // disabled
        if (blacklist.contains(method)) return false;
        
        if (mode == AccessMode.WHITELIST) {
            return whitelist.contains(method);
        } else {
            return true;
        }
    }
    
    public boolean isAllowed(Field method) {
        return isAllowed(new AccessField(method));
    }
    
    public void allow(SecurityKey key, AccessField method) {
        if (this.key == key) whitelist.add(method);
        else throw new SecurityException("Incorrect key");
    }
    
    public void allow(SecurityKey key, Field method) {
        allow(key, new AccessField(method));
    }
    
    public void deny(SecurityKey key, AccessField method) {
        if (this.key == key) blacklist.add(method);
        else throw new SecurityException("Incorrect key");
    }
    
    public void deny(SecurityKey key, Field method) {
        deny(key, new AccessField(method));
    }
    
    public void removeAllowedClass(SecurityKey key, AccessField allowed) {
        if (this.key == key) whitelist.remove(allowed);
        else throw new SecurityException("Incorrect key");
    }
    
    public void removeAllowedClass(SecurityKey key, Field allowed) {
        removeAllowedClass(key, new AccessField(allowed));
    }
    
    public void removeDeniedClass(SecurityKey key, AccessField denied) {
        if (this.key == key) blacklist.remove(denied);
        else throw new SecurityException("Incorrect key");
    }
    
    public void removeDeniedClass(SecurityKey key, Field denied) {
        removeDeniedClass(key, new AccessField(denied));
    }
    
    public void clearWhitelist(SecurityKey key) {
        if (this.key == key) whitelist.clear();
        else throw new SecurityException("Incorrect key");
    }
    
    public void clearBlacklist(SecurityKey key) {
        if (this.key == key) blacklist.clear();
        else throw new SecurityException("Incorrect key");
    }
    
    public record AccessField(
            String cls,
            String name
    ) {
        public AccessField(Field field) {
            this(
                    ClassIdentifier.toInternalName(field.getDeclaringClass()),
                    field.getName()
            );
        }
    }
}
