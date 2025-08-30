# test763 test769 test777 : YAS-android

code:
    manifests/
        AndroidManifest.xml
    java/
        BasicUtil.java
        EncryptUtil.java
        FileUtil.java
        MainActivity.java
        ServiceActivity.java
        YASaes.java
        YASrsa.java
        ZipUtil.java
    res/
        drawable/
            icon_add.xml
            icon_copy.xml
            icon_delete.xml
            icon_edit.xml
            icon_key.xml
            icon_lock.xml
            icon_menu.xml
            icon_process.xml
            icon_run.xml
            icon_send.xml
            icon_shield.xml
            rectangle.xml
        layout/
            address.xml
            dec.xml
            enc.xml
            key_list.xml
            menu.xml
            pdec.xml
            penc.xml
            preceive.xml
            psend.xml
            receive.xml
            send.xml
            toolbar.xml
        values/
            colors.xml
            themes/
                themes.xml (day)
                themes.xml (night

resource:
    drawable - new - vector asset - search, add
    res - new - image asset - add foreground, background image

build:
    file - project structure - dependency, add org.bouncycastle:bcprov-jdk15to18:1.70
    build.gradle.kts - set version info
    ./gradlew.bat [assembleRelease|assembleDebug]
