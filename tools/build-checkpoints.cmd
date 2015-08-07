@echo off
rem Check if the jar has been built.
set TARGET_JAR=build-checkpoints.jar

if not exist "target/%TARGET_JAR%" goto BUILD
goto RUN

:BUILD

echo Compiling BuildCheckpoints to a JAR
cd ..
call mvn package -DskipTests
cd tools

:RUN

for /R "target/" %%F in (%TARGET_JAR%) do set JAR_NAME=%%~nxF
java -jar "target/%JAR_NAME%" %1 %2 %3 %4 %5 %6 %7 %8