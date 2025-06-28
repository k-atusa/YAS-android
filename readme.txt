# test769 : YAS-android

app/manifests/AndroidMenifest.xml

app/java/MainActivity.java
app/java/ServiceActivity.java
app/java/IOmanager.java
app/java/SubActivity.java
app/java/yas_java.java

res/layout/activity_main.xml
res/drawable/alerticon.png (ctrlCV from foreground.png)
res/themes/themes.xml (add noTitleBar to day & night both)

file - project structure - dependency, add org.bouncycastle:bcprov-jdk15to18:1.70
res - new - image asset - foreground.png & background.png

version control at build.gradle.kts
./gradlew.bat [assembleRelease|assembleDebug]
