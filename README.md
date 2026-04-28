# 🛡️ Bluewall
A very lightweight and customizable sandboxed class loader for **Java**.

---
## How it works
**Bluewall** inspects the bytecode using **ASM** at load-time. Ensuring that the classes don't contain denied classes.

## Why Bluewall?
**Bluewall** would be a better alternative to **SecurityManager**. 

Since it checks during load-time and not during the code's execution, it does not impact performance on the running code.

## Installation
Bluewall is hosted on **JitPack**. You can include it to your project via Gradle or Maven.
```groovy
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.MeroSsSany:Bluewall:v1.1.0'
}
```

## Getting Started

### Using `AccessPolicyBuilder`
For version **1.1.0** and higher, you can use `AccessPolicyBuilder`. 
It's a simple class that helps you to create the policies in a builder pattern.

### Creating `AccessPolicyBuilder`
```java
// Create the key
// Make sure you store this
SecurityKey key = new SecurityKey();
        
// Create the policy builder
AccessPolicyBuilder builder = new AccessPolicyBuilder(key);
        
try {
    // Add your policies
    builder
        
        // Adding classes
        .allow(key, System.class) // Put to whitelist
        .deny(key, Runtime.class) // Put to blacklist

        // Adding packages
        .deny(key, Field.class.getPackage())
        .allow(key, String.class.getPackage())
        
        // Adding methods
        .deny(key, System.class.getMethod("exit", int.class)) // Put to blacklist
        .allow(key, System.class.getMethod("setOut", PrintStream.class)) // Put to whitelist
                             
        // Adding fields
        .deny(key, System.class.getField("in"))
        .allow(key, System.class.getField("out"))
            
        // Setting modes
        .setClassAccessMode(key, AccessMode.WHITELIST) // or BLACKLIST
        .setMethodAccessMode(key, AccessMode.BLACKLIST)
        .setFieldAccessMode(key, AccessMode.WHITELIST)
    ;

    // Finally, create the class loader
    SandboxedClassLoader classLoader = builder.build();

    // You can load the classes like this:
    classLoader.defineClassSandboxed(name, bytecode);
                    
} catch (NoSuchMethodException | NoSuchFieldException e) {     
    e.printStackTrace();
}
```

When a security violation is detected, it throws a `SecurityException`.

---

### Alternative: Manually creating the `SandboxedClassLoader`
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
By default, they are on `BLACKLIST` mode.

To change them, use:
```java
policy.setMode(key, AccessMode.BLACKLIST);
```

To add to the whitelist, do:
```java
policy.allow(key, new AccessField(yourField));

// Use this if you don't have java.lang.reflect.Field ready
policy.allow(key, new AccessField("java/lang/System","out")); 
```

To add to the blacklist, do:
```java
policy.deny(key, new AccessMethod(yourMethod));

// Use this if you don't have java.lang.reflect.Field ready
policy.deny(key, new AccessMethod("java/lang/System","exit"));
```

### Running the ClassLoader
```java
classLoader.defineClassSandboxed(name, bytecode);
```
When there's a violation detected, it will throw `SecurityException`

---

### Implementation Notice
1. **`/` vs. `.`**: While registering a class using a `String`, it's important to note to use `/` instead of `.` for packages.
   *(e.g. `java/lang/String`, not `java.lang.String`)*<br><br>
2. **Method Descriptor**: For registering methods, use a `descriptor`. To get the descriptor, use `ClassHelper.toDescriptor(method)`. <br><br>
3. **Getting the Descriptor Manually**: If you don't have `Method`, you have to type the descriptor manually:
   1. Objects written as descriptors are written in the pattern `L<internal name>;` *(e.g. `Ljava/lang/String;`)*
   2. Primitive types are written in **single letter**, such as:
      1. `S`: short
      2. `I`: int
      3. `J`: long
      4. `F`: float
      5. `D`: double
      6. `Z`: boolean
      7. `B`: byte
      8. `C`: char
      9. `V`: void
   3. Primitive types **do not** contain a `;`.
   4. For an array, we simply type `[` before the type. *(e.g. `[Ljava/lang/String;`)*
   5. Method descriptors are usually written in this pattern: `(<params>)<return type>` *(e.g. `([Ljava/lang/String;)V` for `void main(String[] args)`)*<br><br>
4. By default, the sandbox does **not** check reflections as of now.
---

### License
- Protected under: **MIT**
