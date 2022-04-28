using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Diagnostics;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using System.ServiceProcess;


// I made this because I couldn't run seatbelt on an engagement, and I wanted to explorer Windows Service Permissions more.
// Note: this is op sec sloppy because instead of trying to compute file/folder via proper principle group access/permissions I just try to 'open' every service binary and write to every service folder.

namespace SloppyServiceChecker
{
    
    class Program
    {
        static public bool listAllFlag = false;
        static public bool verboseFlag = true;
        static public bool forceFlag = true;
        // Good chunk of this code is stolen from SeatBelt: https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Commands/Windows/ServicesCommand.cs
        static void Main(string[] args)     // TODO: find Unquoted File paths
        {
            // dump arg parsing
            foreach (string argument in args)
            {
                if(argument == "-h")
                {
                    Console.WriteLine("Scenario: We want to find a Service Binary to overwrite. By default will exclude MS binaries that are (I suspect) protected by File Protection. -a or --all to list all");
                    return;

                } else if (argument == "-a" || argument == "--all")
                {
                    listAllFlag = true;
                }else if (argument == "-v" || argument == "--verbose")
                {
                    verboseFlag = true;
                }else if (argument == "-f" || argument == "--force")
                {
                    forceFlag = true;
                }
            }
            // Option: interesting/all -- non-MS,non-Intel
            //      .... unless I can account for windows file protection
            // Do I have write access to the binary?
            //     if the binary isn't there, can I put it there?
            // if it's running can I restart/turn off/turn on
            // if it's not running, can I turn it on?

            // ToDo: write a goat service
            // Service1 binary can be overwritten 
            // Service2 can be stopped/started by anyone
            // Service3 both of the above
            // Service4 binary is missing in a writable directory

            ManagementObjectSearcher wmi = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_service");
            ManagementObjectCollection serviceList = wmi.Get();

            foreach (ManagementObject service in serviceList)
            {
                string companyName = null;
                string description = null;
                string version = null;
                string binaryPathSddl = null;
                string serviceSddl = null;
                bool isDotNet = false;

                string serviceName = (string)service["Name"];
                Console.WriteLine("Name: " + serviceName);


                string serviceCommand = GetServiceCommand(service);
                //Console.WriteLine(" Command:\t" + serviceCommand);

                string binaryPath = GetServiceBinaryPath(serviceCommand);
                //Console.WriteLine(" Bin Path:\t" + binaryPath);

                string serviceDll = GetServiceDll(serviceName);
                //Console.WriteLine(" Service Dll:\t" + serviceDll);

                // ServiceDll could be null if access to the Parameters key is denied 
                //  - Examples: The lmhosts service on Win10 as an unprivileged user
                if (binaryPath.ToLower().EndsWith("\\svchost.exe") && serviceDll != null)
                {
                    binaryPath = serviceDll;
                }

                Console.WriteLine(" Bin Path:\t" + binaryPath);

                if (!string.IsNullOrEmpty(binaryPath) )
                {
                    if (File.Exists(binaryPath))
                    {
                        if (hasWriteAccessToFile(binaryPath))
                        {
                            Console.WriteLine("\tBinary IS Writeable: " + binaryPath + " !");
                            Console.WriteLine("\tDo I have access to restart service? !");
                            if (isServiceRestartable(serviceName))
                            {
                                Console.WriteLine("\t\tYES!");

                            }
                        }

                        // Get information from the binary
                        try
                        {
                            var myFileVersionInfo = FileVersionInfo.GetVersionInfo(binaryPath);
                            companyName = myFileVersionInfo.CompanyName;
                            description = myFileVersionInfo.FileDescription;
                            version = myFileVersionInfo.FileVersion;
                        }
                        catch
                        {
                            Console.WriteLine("ERROR: The file Company, Description, & Version could not be aquired");
                        }

                        // see if we can write next to the file - see if we can do dll hijacking
                        System.IO.DirectoryInfo parentFolder = Directory.GetParent(binaryPath);
                        string containingFolder = parentFolder.ToString();
                        if (hasWriteAccessToFolder(containingFolder))
                        {
                            Console.WriteLine("\tBinary's folder is writable - Dll hijacking is possible"); 
                        }


                    }
                    else
                    {
                        //Console.WriteLine("WOW: The file is MISSING. Is the directory writable? And can I start the service?");
                        bool folderFound = true;
                        string containingFolder = Path.GetDirectoryName(binaryPath);
                        do
                        {
                            try
                            {
                                if (hasWriteAccessToFolder(containingFolder))
                                {
                                    if (containingFolder.Equals(binaryPath))
                                    {
                                        Console.WriteLine("\t[!] Binary is missing and folder IS Writeable: " + containingFolder + " !");
                                    } else
                                    {
                                        Console.WriteLine("\t[!] Binary is missing and folder is missing but it can be created starting: " + containingFolder + " !");
                                    }
                                } else
                                {
                                    Console.WriteLine("\t(Binary is missing BUT folder is NOT Writeable: " + containingFolder + " )");
                                }
                                folderFound = false;
                            } catch (System.IO.DirectoryNotFoundException e)
                            {
                                // the location doesn't exists so I will just keep working up the path
                                //Console.WriteLine("\t\tCould not access: " + containingFolder);
                                System.IO.DirectoryInfo parentFolder = Directory.GetParent(containingFolder);
                                containingFolder = parentFolder.ToString();
                                //Console.WriteLine("\t\tMoving up to : " + containingFolder);
                            }
                        } while (folderFound);

                        // Skip to the next item because if there is no file then we can't obtain the file's info
                        continue;
                    }
                    

                    // skip if MS in the Company Name
                    if (!listAllFlag)
                    {
                        if (companyName != null && Regex.IsMatch(companyName, @"^Microsoft.*", RegexOptions.IgnoreCase))
                        {
                            continue;
                        }
                    }

                    // Collect the rest of the information
                    isDotNet = FileUtil.IsDotNetAssembly(binaryPath);

                    binaryPathSddl = null;
                    try
                    {
                        binaryPathSddl = File.GetAccessControl(binaryPath)
                            .GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine($"ERROR: Could not get the SDDL of service binary '{binaryPath}': Access denied");
                    }

                    // Print the information
                    if (isDotNet)
                    {
                        Console.WriteLine("\t[!] .NET Binary");
                    }

                    Console.WriteLine("\tSDDL: " + binaryPathSddl);     
                    // (A;  = Allow
                    // RP = Read Property
                    // WP = Write Property
                    //if (binaryPathSddl.Contains("RP"))
                    //{
                    //
                    //}
                }

            }  // end for each service in wmi query

            Console.ReadLine();

        }

        private static bool isServiceRestartable(string serviceName)
        {
            // TODO: Actually get service SDDL string
            System.Security.AccessControl.RawSecurityDescriptor sd = new RawSecurityDescriptor("D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY))");
            return true;

            // From https://stackoverflow.com/questions/1454502/how-can-i-restart-a-windows-service-programmatically-in-net/1454564
            /*
            ServiceController service = new ServiceController(serviceName);
            try
            {
                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped);

                
                service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running);
            }
            catch(System.InvalidOperationException err)
            {
                Console.WriteLine("Failed to stop/start service");
                    return false;
            }
            return true;
            */
        }

        public static bool hasWriteAccessToFile(string binaryPath)
        {
            try
            {
                File.Open(binaryPath, FileMode.Open); // Defaults to read and write
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("ERROR: File is suddenly missing. This should never happen");
                return false;
            }catch (UnauthorizedAccessException)
            {
                return false;
            }catch (Exception e)
            {
                Console.WriteLine("ERROR: Trying to access file to see if it's writable: " + e.Message);
                return false;
            }
            return true;
        }

       // From: https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder
       public static bool hasWriteAccessToFolder(string folderPath)
        {

            string fullPath = folderPath + "\\__TEMP__0123456789";  // should never exist
            if (File.Exists(fullPath))
            {
                Console.WriteLine("ERROR: Sloppy folder permission check already exists. This should never happen. Trying to delete...");
                File.Delete(fullPath);
            }
            try
            {
                using (FileStream fs = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write))
                {
                    fs.WriteByte(0xff);
                }

                if (File.Exists(fullPath))
                {
                    File.Delete(fullPath);
                }
            }
            catch (System.UnauthorizedAccessException)
            {
                return false;
            }
            return true;
            
        }

        private static string GetServiceDll(string serviceName)
        {
            // ServiceDll's can be at the following locations
            //  - HKLM\\SYSTEM\\CurrentControlSet\\Services\\ ! ServiceDll
            //    - Ex: DoSvc on Win10
            //  - HKLM\\SYSTEM\\CurrentControlSet\\Services\\Parameters ! ServiceDll
            //    - Ex: DnsCache on Win10

            string path = null;

            try
            {
                path = RegUtil.GetStringValue(RegistryHive.LocalMachine, $"SYSTEM\\CurrentControlSet\\Services\\{serviceName}\\Parameters", "ServiceDll");
            }
            catch
            {
            }

            if (path != null)
                return path;

            try
            {
                path = RegUtil.GetStringValue(RegistryHive.LocalMachine, $"SYSTEM\\CurrentControlSet\\Services\\{serviceName}", "ServiceDll");
            }
            catch
            {
            }

            return path;
        }

        // TODO: Parsing binary paths is hard...
        //  - 1) We don't account for PATHEXT
        //      - Example image path: C:\windows\system32\cmd
        //  - 2) We don't account for the PATH environment variable
        //      - Example image path: cmd.exe
        //      - Example image path: cmd    (combination of 1 & 2) 
        //  - 3) We don't account for per-user services in Win 10 (see https://docs.microsoft.com/en-us/windows/application-management/per-user-services-in-windows)
        private static string GetServiceBinaryPath(string serviceCommand)
        {
            //// The "Path Name" for a service can include a fully quoted path (that includes spaces), as well as
            //// Program arguments (such as the ones that live inside svchost). Some paths, such as Carbon Black's agent)
            //// don't even have a file extension. So it's fair to say that if there are quotes, we'll take what's inside
            //// them, otherwise we'll split on spaces and take the first entry, regardless of its extension).
            //// Example: "C:\Program Files\Windows Defender\MsMpEng.exe"
            //if (command.StartsWith("\""))
            //{
            //    // Quotes are present, so split on quotes. Given that this is a service path,
            //    // it's fair to assume that the path is valid (otherwise the service wouldn't
            //    // be installed) and so we can just rip out the bit between the quotes. This
            //    // split should result in a minimum of 2 parts, so taking the second should
            //    // give us what we need.
            //    return command.Split('"')[1];
            //}
            //else
            //{
            //    // Exmaple image paths we have to deal with:
            //    //   1) C:\Program Files\Windows Identity Foundation\v3.5\c2wtshost.exe
            //    //   2) C:\WINDOWS\system32\msiexec.exe /V
            //    //   3) C:\WINDOWS\system32\svchost.exe -k appmodel -p
            //    if (File.Exists(command))  // Case 1
            //    {
            //        return command;
            //    }
            //    else // Case 2 & 3
            //    {
            //        return command.Split(' ')[0];
            //    }
            //}

            var path = Regex.Match(serviceCommand, @"^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*", RegexOptions.IgnoreCase);
            return path.Groups[1].ToString();
        }

        private static string GetServiceCommand(ManagementObject service)
        {
            // Get the service's path.  Sometimes result["PathName"] is not populated, so
            // in those cases we'll try and get the value from the registry. The converse is
            // also true - sometimes we can't acccess a registry key, but result["PathName"]
            // is populated
            string serviceCommand = null;
            if (service["PathName"] != null)
            {
                serviceCommand = ((string)service["PathName"]).Trim();
                if (serviceCommand == string.Empty)
                {
                    serviceCommand = GetServiceCommandFromRegistry((string)service["Name"]);
                }
            }
            else
            {
                serviceCommand = GetServiceCommandFromRegistry((string)service["Name"]);
            }

            return serviceCommand;
        }

        private static string GetServiceCommandFromRegistry(string serviceName)
        {
            try
            {
                return RegUtil.GetStringValue(RegistryHive.LocalMachine, $"SYSTEM\\CurrentControlSet\\Services\\{serviceName}", "ImagePath");
            }
            catch
            {
                return null;
            }
        }
    }
}
