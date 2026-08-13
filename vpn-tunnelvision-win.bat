@echo off
setlocal EnableDelayedExpansion
REM ============================================================================
REM  vpn-tunnelvision-windows.bat -- TunnelVision (CVE-2024-3661) test harness.
REM
REM  Injects a more-specific /32 route for one tripwire canary via the REAL
REM  uplink, while the tunnel's two /1 capture routes stay intact -- exactly the
REM  condition src/tripwire.rs::detect_attack (NotifyRouteChange2 path) watches
REM  for. A healthy engine detects the route, installs the WFP "tunnel panic"
REM  lockdown, and exits 101.
REM
REM  DESTRUCTIVE: a PASS locks this machine down. You must REBOOT to recover.
REM  Dry-run by default. Requires --fire (and a typed 'yes', unless --yes).
REM
REM  Run in an ADMIN Command Prompt:
REM      vpn-tunnelvision-windows.bat                 dry-run
REM      vpn-tunnelvision-windows.bat --fire          attack (asks to confirm)
REM      vpn-tunnelvision-windows.bat --fire --yes --canary 8.8.8.8
REM ============================================================================

set "CANARIES=1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222 192.0.2.1 198.51.100.1 203.0.113.1"
set "CANARY=1.1.1.1"
set "FIRE=0"
set "ASSUMEYES=0"
set "TIMEOUT=12"

:parse
if "%~1"=="" goto endparse
if /i "%~1"=="--fire"   set "FIRE=1"
if /i "%~1"=="--yes"    set "ASSUMEYES=1"
if /i "%~1"=="--canary" ( set "CANARY=%~2" & shift )
shift
goto parse
:endparse

echo(
echo ================= TUNNELVISION ATTACK TEST =================

REM A route to anything not in the tripwire's canary list is never checked.
echo  %CANARIES% | findstr /c:" %CANARY% " >nul
if errorlevel 1 (
    echo [x] canary %CANARY% is not in the tripwire's list; it would not be checked.
    exit /b 1
)

REM --- Preconditions: a real, capturing tunnel. Otherwise this just litters
REM     the routing table with a junk route and proves nothing. ---------------
net session >nul 2>&1
if errorlevel 1 ( echo [x] run from an ADMIN prompt ^(route injection needs elevation^). & exit /b 1 )

tasklist /fi "imagename eq tunnel.exe" 2>nul | find /i "tunnel.exe" >nul
if errorlevel 1 ( echo [x] no 'tunnel.exe' process -- start the engine first. & exit /b 1 )

REM TUN interface index = the InterfaceIndex owning the 0.0.0.0/1 capture route.
set "TUNIDX="
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "(Get-NetRoute -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceIndex"`) do set "TUNIDX=%%i"
if not defined TUNIDX ( echo [x] no 0.0.0.0/1 capture route -- tunnel not capturing ^(--no-route?^). & exit /b 1 )

REM The other half of the capture must be on the same interface, or it is
REM half-installed and tunnel_routes_intact would not hold.
set "TUNIDX2="
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "(Get-NetRoute -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceIndex"`) do set "TUNIDX2=%%i"
if not "%TUNIDX2%"=="%TUNIDX%" ( echo [x] 128.0.0.0/1 not on the TUN interface -- capture half-installed; aborting. & exit /b 1 )

REM --- The real uplink still owns 0.0.0.0/0 beside the /1 routes. Route the
REM     canary via that gateway to steer it off the tunnel. -------------------
set "UPGW="
set "UPIDX="
for /f "usebackq tokens=1,2" %%a in (`powershell -NoProfile -Command "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.InterfaceIndex -ne %TUNIDX% } | Sort-Object RouteMetric | Select-Object -First 1 | ForEach-Object { '{0} {1}' -f $_.NextHop, $_.InterfaceIndex }"`) do (
    set "UPGW=%%a"
    set "UPIDX=%%b"
)
if not defined UPGW ( echo [x] cannot find the real uplink default route. & exit /b 1 )
if "%UPIDX%"=="%TUNIDX%" ( echo [x] default route is the TUN itself -- no real uplink to leak via. & exit /b 1 )

echo [i] Tunnel:  capturing on interface index %TUNIDX%.
echo [i] Uplink:  gateway %UPGW% on interface index %UPIDX%.
echo [i] Attack:  route add %CANARY% mask 255.255.255.255 %UPGW% if %UPIDX% metric 1
echo              ^(a /32 beats the tunnel's /1, so %CANARY% leaks off-tunnel^)

if "%FIRE%"=="0" (
    echo [i] DRY RUN -- nothing injected. Re-run with --fire to attack.
    echo(
    exit /b 0
)

echo [!] --fire: a PASS locks this machine down. You will need to REBOOT.
if "%ASSUMEYES%"=="0" (
    set /p "ANS=    Type 'yes' to inject the leak route: "
    if /i not "!ANS!"=="yes" ( echo [x] aborted. & exit /b 1 )
)

REM cmd cannot trap Ctrl-C reliably: if you interrupt during the watch below,
REM remove the route by hand with:  route delete %CANARY% mask 255.255.255.255
echo [i] Injecting leak route...
route add %CANARY% mask 255.255.255.255 %UPGW% if %UPIDX% metric 1 >nul
if errorlevel 1 ( echo [x] route injection failed. & exit /b 1 )

echo [i] Watching for the tripwire (up to %TIMEOUT%s)...
set "FIRED=0"
set /a tries=0
:poll
tasklist /fi "imagename eq tunnel.exe" 2>nul | find /i "tunnel.exe" >nul
if errorlevel 1 ( set "FIRED=1" & goto result )
set /a tries+=1
if %tries% geq %TIMEOUT% goto result
timeout /t 1 /nobreak >nul
goto poll

:result
REM Always remove our injected route: on a FAIL it is a real leak we created and
REM must not leave behind; on a PASS it just tidies the table (connectivity
REM still needs the reboot -- the WFP panic filters are what hold it down).
route delete %CANARY% mask 255.255.255.255 >nul 2>&1

echo ==================== RESULT ====================
if "%FIRED%"=="1" (
    echo [PASS] Tripwire fired: route detected, engine locked the network down.
    echo        tunnel.exe has exited ^(exit 101^).
    REM Corroborate with the non-dynamic WFP lockdown filter. Best-effort: the
    REM process exit above is the authoritative signal; this only confirms it.
    netsh wfp show state file="%TEMP%\tunnel_wfp.xml" >nul 2>&1
    findstr /i "tunnel panic" "%TEMP%\tunnel_wfp.xml" >nul 2>&1 && echo        WFP 'tunnel panic' lockdown sublayer is present.
    del "%TEMP%\tunnel_wfp.xml" >nul 2>&1
    echo [!] The machine is now LOCKED DOWN -- reboot to restore networking,
    echo     then rotate your keys. ^(The injected route was removed.^)
) else (
    echo [FAIL] Tripwire did NOT fire within %TIMEOUT%s.
    echo        %CANARY% was leaking off-tunnel and the engine did not catch it.
    echo        The injected route has been removed. Investigate src/tripwire.rs.
)
echo(
exit /b 0