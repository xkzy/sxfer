@echo off
REM ==========================================
REM sxfer - Windows Receiver Example
REM ==========================================

echo [sxfer] Starting Receiver on COM3...
echo [sxfer] Incoming files will be saved to the 'received_data' folder.
echo.

REM Create the output directory if it doesn't exist
if not exist "received_data" mkdir received_data

REM Run the receiver
REM Use -d to specify your COM port (e.g. COM3)
REM Use -o to specify the output directory
sxfer.exe recv -d COM3 -o .\received_data

pause
