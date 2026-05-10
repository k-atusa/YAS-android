# Android Project

```python
mainfests/
    AndroidManifest.xml #set main activity, service, permissions
java/
    com.example.package/
        code.java #codes here
assets/ #app - new - folder - asset folder
    data.html #datas that can be used by app
res/
    drawable/ #drawable - new - vector asset - search, add
        icon.xml #icon or component xml
    layout/
        mainview.xml #screen xml
    mipmap/ #res - new - image asset - add foreground, background image
    values/
        themes/ #general button, background design
        colors.xml
        strings.xml
        styles.xml #defines component design
    xml/
        config.xml #config for some apps
build.gradle.kts #file - project structure - dependency - add, version info
```

- Align and Sign Release build with jks keyfile
- There is two memory limit: Device limit and VM limit
    - Modern Android device RAM is 6~16 GB
    - But memory that one process can use is limited as VM memory, usually 256 MB
    - Use independent process to bypass this limit
- Declare largeheap in AndroidManifest to extend VM limit to 512 MB
- JNI Native Calls are not limited by VM memory
