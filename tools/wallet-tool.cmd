@echo off

rem  Copyright by the original author or authors.
rem
rem  Licensed under the Apache License, Version 2.0 (the "License");
rem  you may not use this file except in compliance with the License.
rem  You may obtain a copy of the License at
rem
rem      http://www.apache.org/licenses/LICENSE-2.0
rem
rem  Unless required by applicable law or agreed to in writing, software
rem  distributed under the License is distributed on an "AS IS" BASIS,
rem  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem  See the License for the specific language governing permissions and
rem  limitations under the License.

rem Check if the jar has been built.
set TARGET_JAR=wallet-tool.jar

if not exist "target/%TARGET_JAR%" goto BUILD
if defined ALWAYS_BUILD_WALLETTOOL goto BUILD
goto RUN

:BUILD

echo Compiling WalletTool to a JAR
cd ..
call mvn package -DskipTests
cd tools

:RUN

for /R "target/" %%F in (%TARGET_JAR%) do set JAR_NAME=%%~nxF
java -jar "target/%JAR_NAME%" %1 %2 %3 %4 %5 %6 %7 %8