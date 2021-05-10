# ServiceSurvey
Quick script to enumerate services with particular focus on services listening on network interfaces from user land. This is mainly for events like CCDC (https://www.nationalccdc.org/) where I (as a Red Teamer) land on a victim machine and I want to know what services (and their executable binaries) are listening on which ports.

## Why?
I could not find a easy/simple command in Windows to tell me what service executable was listening on a specific port

## Future ToDo:
- Deduplicate the output
- Make a .NET version
- PrivEsc Check: Automatically check the binary's permissions 
- Automaticallly check the service's permissions to see if Everyone can shut it down
- Check service config permissions
- Search for scheduled tasks that might affect the service
