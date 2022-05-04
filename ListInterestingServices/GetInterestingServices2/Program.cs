using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
/* What: This program combines .NET and WMI information and prints interesting service information
 * Why: When I have landed on a new machine, I want to know what this machine is used for, if it's services have any creds. 
 * To get on a machine you usually have to have admin, so we're assuming that and not printing CanStop/CanStart
 * 
 * List the non-standard/newish services
 * List the services and their binaries and what ports they are listing on
 * Look for conf/ini files in the service directories
 * Look for 'interesting' config information in registry... don't know  a good way to find that
 * 
 * ToDo: 
 * - List listening ports
 * - Test DisplayName - looks like a known bug: https://stackoverflow.com/questions/50177003/windows-2016-servicecontroller-displayname-returns-servicecontroller-servicenam
 * - Fill in InstallDate based on file 
 * 
 * Maybe:
 *  - Gather service intel from the registry
 *  - Gather service intel from powershell's 'Get-Service' because powershell sometimes has more access to things
 *  - Gather service intel from COM objects
 *  - Get Listening processes   https://stackoverflow.com/questions/3956285/list-used-tcp-port-using-c-sharp
        ipGlobalProperties.GetActiveTcpListeners();
 *  
 *  Questions:
 *      Investigate what happens when there's mutliple binary paths!
 *      What weird values can I put in the registry for a service name? Like a null in the middle of a stream?
 *      
 *  
 *
 *  
 * */
namespace GetInterestingServices2
{
    class serviceObj
    {
        public bool isInteresting = false; // Listing on a port, or non-MS signed
        static public List<String> knownNobinPathServiceNames = new List<string> {
            "ADOVMPPackage",
            "adsi",
            "Beep",
            "CimFS",
            "clr_optimization_v2.0.50727_32",
            "clr_optimization_v2.0.50727_64",
            "clr_optimization_v4.0.30319_32",
            "clr_optimization_v4.0.30319_64",
            "CoreUI",
            "CPK1HWU",
            "CPK2HWU",
            "crypt32",
            "DCLocator",
            "ESENT",
            "exfat",
            "fastfat",
            "Fs_Rec",
            "ialm",
            "iaStorAV",
            "ldap",
            "Lsa",
            "Msfs",
            "MsRPC",
            "MSSCNTRS",
            "napagent",
            "NetbiosSmb",
            "Npfs",
            "NTDS",
            "Ntfs",
            "Null",
            "PortProxy",
            "RDMANDK",
            "RDPNP",
            "RDPUDD",
            "Realtek",
            "ReFS",
            "ReFSv1",
            "TCPIP6TUNNEL",
            "TCPIPTUNNEL",
            "TSDDD",
            "workerdd",
        };

        // if null, set. If already set, and new Value is different, echo
        // ... what do I want to see? Do I care that WMI has a different view? Not really... I just want to see 'interesting' services
        public string Name { get; internal set; }
        public serviceObj(string name)
        {
            Name = name;
        }


        public serviceObj()
        {
        }


        private string _DisplayName;
        public string DisplayName {
            get { return _DisplayName; }
            set
            {
                if (_DisplayName == null)
                    _DisplayName = value;
                else if (_DisplayName == value || "" == value.ToString()) { }
                else
                    Console.WriteLine("Diff DisplayName: {0} vs. {1}", _DisplayName, value);
            } 
        }

        private bool _CanPauseAndContinue; // because bool can't be null
        public bool CanPauseAndContinue { get; internal set; }

        private bool _CanShutdown; // because bool can't be null
        public bool CanShutdown { get; internal set; }

        private bool _CanStop;  // because bool can't be null
        public bool CanStop { get; internal set; }

        //private ServiceStartMode _StartType;  // starts as 'boot' by default
        private String _StartType;
        public String StartType
        {
            get { return _StartType; }
            set
            {
                if (_StartType == null)
                    _StartType = value;
                else if (_StartType == value || "" == value.ToString()) { }
                else
                    Console.WriteLine("Diff StartType: {0} vs. {1}", _StartType, value);
            }
        }

        //private ServiceControllerStatus _Status;
        private string _Status;
        public string Status
        {
            get { return _Status; }
            set
            {
                if (_Status == null)
                    _Status = value;
                else if (_Status == value || "" == value) { }
                else if (_Status == "Running" && "OK" == value) { }
                else if (_Status == "Stopped" && "OK" == value) { }
                else if ("UNKNOWN" == value) { }
                else
                    Console.WriteLine("Diff Status: {0} (current) vs. {1} (new)", _Status, value);
            }
        }

        private string _binPath;
        private string _CommandLine;
        public string CommandLine
        {
            get { return _CommandLine; }
            set
            {
                if (_CommandLine == null)
                    _CommandLine = value;
                else if (_CommandLine == value || "" == value) { }
                else
                    Console.WriteLine("Diff PathName: {0} (current) vs. {1} (new)", _CommandLine, value);

                // Interesting rules
                if (!_CommandLine.ToLower().Trim('"').Trim('\'').StartsWith(@"c:\windows"))
                    isInteresting = true;

                if (extractBinPath(_CommandLine) && File.Exists(_binPath))
                {
                    // Get install time based on newest date
                    DateTime writeTime = System.IO.File.GetLastWriteTime(_binPath);
                    DateTime creationTime = System.IO.File.GetCreationTime(_binPath);
                    // Get the newest timestamp because installers sometimes preserve the timestamps from their containers 
                    if (writeTime < creationTime)
                        InstallDate = creationTime;
                    else
                        InstallDate = writeTime;
                }


                
                
            }
        }

        private bool extractBinPath(string cmdLine)
        {
            if (serviceObj.knownNobinPathServiceNames.Contains(Name))
                return false;

            cmdLine = cmdLine.Trim('"');
            cmdLine = cmdLine.Replace("\"", "");
            cmdLine = cmdLine.Trim();
            // Normalize the path
            //Console.WriteLine("Pre:   " + cmdLine);
            if (cmdLine.ToLower().StartsWith("\\systemroot"))
                cmdLine = cmdLine.ToLower().Replace("\\systemroot", "%SystemRoot%");
            if (cmdLine.ToLower().StartsWith("system32"))
                cmdLine = cmdLine.ToLower().Replace("system32", "%SystemRoot%\\System32");
            if (cmdLine.ToLower().StartsWith("syswow64"))
                cmdLine = cmdLine.ToLower().Replace("syswow64", "%SystemRoot%\\SysWOW64");
            if (cmdLine.ToLower().StartsWith(@"\\\?\?\\"))
                cmdLine = cmdLine.Replace(@"\\\?\?\\", "");
            cmdLine = Environment.ExpandEnvironmentVariables(cmdLine);
            //Console.WriteLine("Post: " + cmdLine);

            cmdLine = cmdLine.Trim('"');
            cmdLine = cmdLine.Trim();

            string justExePath = "";
            string binPath = "";
            string[] parts = cmdLine.Split(' ');

            if (parts.Length == 1)
            {
                justExePath = parts[0];
                if (File.Exists(justExePath))
                {
                    binPath = justExePath;
                }
            }
            else
            {
                for (int i = 0; i <= parts.Length; i++)
                {
                    string[] pathParts = new string[cmdLine.Length];
                    Array.Copy(parts, pathParts, i);

                    justExePath = String.Join(" ", pathParts);
                    //Console.WriteLine("Checking: " + justExePath);
                    if (File.Exists(justExePath))
                    {
                        //Console.WriteLine("\tFound: " + justExePath);
                        _binPath = justExePath;
                        return true; 
                    }
                }
            }

            return false ;
        }

        private string _ProcessId;
        public string ProcessId
        {
            get { return _ProcessId; }
            set
            {
                if (_ProcessId == null)
                    _ProcessId = value;
                else if (_ProcessId == value || "" == value) { }
                else
                    Console.WriteLine("Diff ProcessId: {0} (current) vs. {1} (new)", _ProcessId, value);
            }
        }


        private string _StartName;
        public string StartName
        {
            get { return _StartName; }
            set
            {
                if (_StartName == null)
                    _StartName = value;
                else if (_StartName == value || "" == value) { }
                else
                    Console.WriteLine("Diff StartName: {0} (current) vs. {1} (new)", _StartName, value);
            }
        }

        public DateTime InstallDate { get; internal set; }

        private List<String> _PortList;
        public string GetPortListCSV()
        {
            if (_PortList == null)
                return "";
            return String.Join(",", _PortList);
        }
        internal void AddListeningPort(string port_number)
        {
            if(_PortList == null)
            {
                _PortList = new List<string> { port_number };
            }
            else if (!_PortList.Contains(port_number.Trim()))
            {
                _PortList.Add(port_number.Trim());
            }

            isInteresting = true;
        }
    } // end serviceObj class
    class Program
    {
        static bool printAll = false;
        static void Main(string[] args)
        {
            Dictionary<string, serviceObj> serviceDict = new Dictionary<string, serviceObj>();
            foreach (ServiceController existingService in ServiceController.GetServices())
            {
                var service = new serviceObj();
                service.Name = existingService.ServiceName;
                service.DisplayName = existingService.DisplayName;
                service.CanPauseAndContinue = existingService.CanPauseAndContinue;
                service.CanShutdown = existingService.CanShutdown;
                service.CanStop = existingService.CanStop;
                service.StartType = existingService.StartType.ToString();
                service.Status = existingService.Status.ToString();     // Returns more/better information

                serviceDict.Add(service.Name, service);
            }

            
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service");
            var collection = searcher.Get().Cast<ManagementBaseObject>();
            // This is +		thing	{\\XPSTAU\root\cimv2:Win32_Service.Name="AdobeARMservice"}	System.Management.ManagementBaseObject {System.Management.ManagementObject}
            // If this locks up, I might have to specify in the query, exactly the fields I want
            foreach (var wmiService in collection)
            {
                //foreach(var prop in wmiService.Properties)
                //    Console.WriteLine(prop.Name, prop.Value, prop.IsLocal, prop.IsArray);
                string name = wmiService.GetPropertyValue("Name").ToString();
                if(!serviceDict.ContainsKey(name))
                {
                    Console.WriteLine("ATTENION: Hidden service found with WMI: " + name);
                    var hiddenService = new serviceObj(name);
                    serviceDict.Add(name, hiddenService);
                }
                //Console.WriteLine("Adding WMI information to service " + name);
                serviceDict[name].Status = Convert.ToString(wmiService.GetPropertyValue("Status"));
                serviceDict[name].Status = Convert.ToString(wmiService.GetPropertyValue("State"));
                serviceDict[name].DisplayName = wmiService.GetPropertyValue("DisplayName").ToString();
                serviceDict[name].CommandLine = Convert.ToString(wmiService.GetPropertyValue("PathName"));
                serviceDict[name].ProcessId = Convert.ToString(wmiService.GetPropertyValue("ProcessId"));
                serviceDict[name].StartName = Convert.ToString(wmiService.GetPropertyValue("StartName"));          // the user like LocalSystem
                //serviceDict[name].InstallDate = Convert.ToString(wmiService.GetPropertyValue("InstallDate"));    // no data is ever returned but I can still hope
                /*  AcceptPause
                    AcceptStop
                    Caption
                    CheckPoint
                    CreationClassName
                    DelayedAutoStart
                    Description
                    DesktopInteract
                    [Done] DisplayName
                    ErrorControl
                    ExitCode
                    InstallDate
                    [Done] Name
                    [Done] PathName
                    [Done] ProcessId
                    ServiceSpecificExitCode
                    ServiceType
                    Started
                    StartMode
                    [Done] StartName
                    [Done] State
                    [Done] Status
                    SystemCreationClassName
                    SystemName  // aka hostname
                    TagId
                    WaitHint            */
            } // End WMI enrichment

            tasklistEnrichment(serviceDict);

            // TODO
            netstatEnrichment(serviceDict);

            // TODO
            registryEnrichment(serviceDict);

            // TODO: Grap the latest Mod or Creation times and order the output list by that
            //fileDataEnrichment(serviceDict);

            printPrint(serviceDict);

            Console.WriteLine("Done");
        }

        private static void registryEnrichment(Dictionary<string, serviceObj> serviceDict)
        {
            RegistryKey serviceList = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");

            // Check to see if there were any subkeys
            if (serviceList.SubKeyCount > 0)
            {
                foreach (string serviceName in serviceList.GetSubKeyNames())
                {
                    //Console.WriteLine(serviceName);
                    RegistryKey serviceKey = serviceList.OpenSubKey(serviceName);
                    string cmdLine = "";
                    var values = serviceKey.GetValueNames();
                    if (serviceKey.GetValueNames().Contains("ImagePath"))
                    {
                        //Console.WriteLine("\t" + serviceKey.GetValue("ImagePath"));
                        cmdLine = (String)serviceKey.GetValue("ImagePath");
                    }
                    else if (serviceKey.GetValueNames().Contains("ServiceDll"))  // actually this is a key and the value it holds is 
                    {
                        //Console.WriteLine("\t" + serviceKey.GetValue("ServiceDll"));
                        cmdLine = (String)serviceKey.GetValue("ServiceDll");
                    }else if (serviceKey.GetValueNames().Contains("ProviderPath"))  // actually this is a key and the value it holds is 
                    {
                        //Console.WriteLine("\t" + serviceKey.GetValue("ProviderPath"));
                        cmdLine = (String)serviceKey.GetValue("ProviderPath");
                    }
                    else if (serviceKey.GetValueNames().Contains("MofImagePath"))
                    {
                        //Console.WriteLine("\t" + serviceKey.GetValue("MofImagePath"));
                        cmdLine = (String)serviceKey.GetValue("MofImagePath");
                    }else if (serviceKey.GetValueNames().Contains("Library"))
                    {
                        //Console.WriteLine("\t" + serviceKey.GetValue("Library"));
                        cmdLine = (String)serviceKey.GetValue("Library");
                    }
                    else if (serviceKey.GetSubKeyNames().Contains("Parameters")) // RegistryKey serviceList = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                    {
                        RegistryKey paramSubkey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName + "\\Parameters");
                        if (paramSubkey.GetValueNames().Contains("ServiceDll"))
                        {
                            cmdLine = (String)paramSubkey.GetValue("ServiceDll");
                        }
                    }
                    else if (serviceKey.GetSubKeyNames().Contains("Performance")) // RegistryKey serviceList = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                    {
                        // Should have caught 
                        // MSDTC Bridge 3.0.0.0, PerfDisk, PerfNet
                        // Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC Bridge 3.0.0.0\Performance\Library
                        RegistryKey paramSubkey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName + "\\Performance");
                        if (paramSubkey.GetValueNames().Contains("Library"))
                        {
                            cmdLine = (String)paramSubkey.GetValue("Library");
                        }
                    }
                    else
                    {
                        if(!serviceObj.knownNobinPathServiceNames.Contains(serviceName))
                            Console.WriteLine("  Interesting: No Binary for this service: " + serviceName);
                    }
                    // Maybe:
                    // Performance \Library
                    // Parameters \ServiceDll

                    if (cmdLine == "")
                        continue;

                    // assign it to the correct service
                    foreach (KeyValuePair<string, serviceObj> item in serviceDict)
                    {
                        if (item.Value.Name == serviceName)
                        {
                            //Console.WriteLine("{0} (PID {1} {2}) listening on {3} ", item.Value.Name, pid1, pid2, port_number);
                            item.Value.CommandLine = cmdLine;
                         }
                    }
                    
                    

                    
                    //foreach (var sub in serviceKey.GetSubKeyNames())
                    //{
                    //    //Console.WriteLine("\t" + sub);
                    //}
                }
            }
        }

        private static void fileDataEnrichment(Dictionary<string, serviceObj> serviceDict)
        {
            // TODO: Grap the latest Mod or Creation times and order the output list by that
        }


        // Copy pasted from https://www.cheynewallace.com/get-active-ports-and-associated-process-names-in-c/
        private static void netstatEnrichment(Dictionary<string, serviceObj> serviceDict)
        {
            try
            {
                using (Process p = new Process())
                {

                    ProcessStartInfo ps = new ProcessStartInfo();
                    ps.Arguments = "-a -n -o";
                    ps.FileName = "netstat.exe";
                    ps.UseShellExecute = false;
                    ps.WindowStyle = ProcessWindowStyle.Hidden;
                    ps.RedirectStandardInput = true;
                    ps.RedirectStandardOutput = true;
                    ps.RedirectStandardError = true;

                    p.StartInfo = ps;
                    p.Start();

                    StreamReader stdOutput = p.StandardOutput;
                    StreamReader stdError = p.StandardError;

                    string content = stdOutput.ReadToEnd() + stdError.ReadToEnd();
                    string exitStatus = p.ExitCode.ToString();

                    if (exitStatus != "0")
                    {
                        Console.WriteLine("Error running Netstat!");
                        // Command Errored. Handle Here If Need Be
                    }

                    //Get The Rows
                    string[] rows = Regex.Split(content, "\r\n");
                    foreach (string row in rows)
                    {
                        if (!row.Contains("LISTENING"))
                            continue;
                        if (row.Contains("127.0.0.1"))
                            continue;

                        //Split it baby
                        string[] tokens = Regex.Split(row, "\\s+");
                        if (tokens.Length > 4 && (tokens[1].Equals("UDP") || tokens[1].Equals("TCP")))
                        {
                            String pid1 = "";
                            String pid2 = "";

                            string localAddress = Regex.Replace(tokens[2], @"\[(.*?)\]", "1.1.1.1");
                            string protocol = localAddress.Contains("1.1.1.1") ? String.Format("{0}v6", tokens[1]) : String.Format("{0}v4", tokens[1]);
                            string port_number = localAddress.Split(':')[1];
                            if (tokens[1] == "UDP")
                            {
                                //pid1 = Convert.ToInt16(tokens[4]);
                                pid1 = tokens[4];  // TODO make these real ints
                            }
                            else
                            {
                                //pid2 = Convert.ToInt16(tokens[5]); 
                                pid2 = tokens[5];
                            }

                            // insert the data in the service list
                            foreach (KeyValuePair<string, serviceObj> item in serviceDict)
                            {
                                if (item.Value.ProcessId == pid1 || item.Value.ProcessId == pid2)
                                {
                                    //Console.WriteLine("{0} (PID {1} {2}) listening on {3} ", item.Value.Name, pid1, pid2, port_number);
                                    item.Value.AddListeningPort(port_number);
                                }
                            }
                        } // end foreach
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        private static void tasklistEnrichment(Dictionary<string, serviceObj> serviceDict)
        {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = "tasklist.exe";
            p.StartInfo.Arguments = "/svc /fo csv";
            p.Start();
            string tasklistOutput = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            //Console.Write(output);

            String[] lines = tasklistOutput.Split('\n');
            lines = lines.Skip(1).ToArray();

            foreach (string line in lines)
            {
                // TODO: This
                // "System Idle Process","0","N/A"
                // "svchost.exe","1240","BrokerInfrastructure,DcomLaunch,PlugPlay,Power,SystemEventsBroker"
                //Console.Write(line);
            }


            return;
        }

        private static void printPrint(Dictionary<string, serviceObj> serviceDict)
        {
            //      Name, DisplayName, StartName, InstallDate, Status,PortList    PathName
            //string formatString = "{0,28} |{1,42} |{2,10} |{3,10} |{4,10} | {5,48}  ";
            string formatString = "{0,28} ,{1,42} ,{2,10} ,{3,10} ,{4,10} , {5,48}  ";
            Console.WriteLine("Interesting:");
            foreach (KeyValuePair<string, serviceObj> item in serviceDict)
            {
                // ToDo: Sort by: Ports, Running, 
                if (item.Value.isInteresting)
                    Console.WriteLine(formatString, item.Value.Name, item.Value.DisplayName, item.Value.InstallDate, item.Value.Status,  item.Value.GetPortListCSV(), item.Value.CommandLine.Trim());
            }

            if (printAll)
            {
                Console.WriteLine();
                Console.WriteLine("All:");
                foreach (KeyValuePair<string, serviceObj> item in serviceDict)
                {
                    Console.WriteLine(formatString, item.Value.Name, item.Value.DisplayName, item.Value.InstallDate, item.Value.Status,  item.Value.GetPortListCSV(), item.Value.CommandLine);
                }
            }
            
        }
    }
}
