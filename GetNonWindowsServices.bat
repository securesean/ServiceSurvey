TODO: Add unquoted service paths
for /f "tokens=2 delims='='" %%a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %%a