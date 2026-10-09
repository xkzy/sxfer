@echo off
REM ==========================================
REM sxfer - Windows Sender Example
REM ==========================================

echo [sxfer] Starting Sender on COM4...
echo.

REM Create a dummy directory and file to send if they don't exist
if not exist "data_to_send" mkdir data_to_send
if not exist "data_to_send\hello.txt" echo Hello from sxfer! > data_to_send\hello.txt

echo [sxfer] Transmitting contents of 'data_to_send' folder...

REM Run the sender
REM Use -d to specify your COM port (e.g. COM4)
REM You can also add -z 9 for maximum compression, or -m scramble for scrambled modulation
sxfer.exe send -d COM4 .\data_to_send

echo.
echo [sxfer] Transmission complete!
pause
