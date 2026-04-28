# 🛡️ Bluewall
A very lightweight and customizable sandboxed class loader for **Java**.

---
## How it works
**Bluewall** inspects the bytecode using **ASM** at load-time. Ensuring that the classes doesn't contain denied classes.

## Why Bluewall?
**Bluewall** would be a better alternative to **SecurityManager**. 

Since it checks during load-time and not during the code's execution, it does not impact performance on the running code.

## Getting Started

### Creating the `SandboxedClassLoader`
First, to create the `SandboxedClassLoader`, you need to create a `new SecurityKey`.
```java
SecurityKey key = new SecurityKey();
```
Then create the access policies.
```java
ClassAccessPolicy clsPolicy = new ClassAccessPolicy(key);
MethodAccessPolicy methodPolicy = new MethodAccessPolicy(key);
FieldAccessPolicy fieldPolicy = new FieldAccessPolicy(key);
```

Finally, you can create the sandboxed class loader:
```java
SandboxedClassLoader classLoader = new SandboxedClassLoader(
        clsPolicy, methodPolicy, fieldPolicy
);
```

### Adding Access Policies
The polices operate on 2 modes: `WHITELIST` and `BLACKLIST`.
By default, they are on `WHITELIST` mode.

To change them, use:
```java
policy.setMode(key, AccessMode.BLACKLIST);
```

To add to the whilelist, do:
```java
policy.allow(key, new AccessField(yourField));

// Use this if you don't have java.lang.reflect.Field ready
policy.allow(key, new AccessField("java/lang/System","out")); 
```

To add to the blacklist, do:
```java
policy.deny(key, new AccessField(yourField));

// Use this if you don't have java.lang.reflect.Field ready
policy.deny(key, new AccessField("java/lang/System","exit"));
```

### Running the ClassLoader
```java
classLoader.defineClassSandboxed(name, bytecode);
```
When there's a violation detected, it will throw `SecurityException`

---

### License
Protected under: **MIT**
