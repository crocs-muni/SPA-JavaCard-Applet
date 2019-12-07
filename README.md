# SBAPR-2019-JCApplet

This is applet for smartcards supporting JavaCard platform.
This applet was created as a part of a Bachelor thesis focused on obtaining powertraces of basic cryptografic operations.
Each cryptographic operation is delimited by operations of random number generation.

This repository also contains build applets (CAP files) that can be directly installed on smart card.
There are 3 versions, each for different JavaCard SDK version.

**Compiling**

Source code in Java can be developed and then compiled/converted to CAP (file installable on JavaCard) by https://github.com/crocs-muni/javacard-gradle-template-edu using Ant JavaCard.

Here is my workflow using mentioned tool (used in command line):
1. Put applet class into .\javacard-gradle-template-edu\applet\src\main\java\applet
2. If gradle is not installed use gradlew.bat in .\javacard-gradle-template-edu
3. Modify build.gradle file in .\javacard-gradle-template-edu\applet
	You can change AID
	Usually all what is needed to do is to change package or class name
4. Then run gradlew buildJavaCard  --info --rerun-tasks
5. If everything ended successfully .cap file should be in .\javacard-gradle-template-edu\applet\build
6. All done now, we can now proceed to applet installing

**Installing**

For installing applet I used Global Platform Pro (https://github.com/martinpaljak/GlobalPlatformPro).

Here I mention my workflow (used in command line):
1. Simply navigate in cmd to the directory where is gp.exe or add path to environment variables
2. Basic commands:
 * gp -h help
 * gp -l lists installed applets on the card
 * gp --install #path_to_cap_file installs applet
 * gp --delete #package_id deletes package by id 
 * gp --uninstall #path_to_installed_applet_on_your_pc deletes applet
 * gp --applet #applet_id --apdu #apdu_id sends apdu on specified applet
