using System;
using System.Text;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net;
using System.DirectoryServices;
using System.Xml.Linq;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Collections;
using System.Security.Cryptography;

namespace adaclscan
{
    class Program
    {
        static Dictionary<string, string> mapSid_DN = new Dictionary<string, string>();
        static Dictionary<string, string> mapDN_Path = new Dictionary<string, string>();
        static StreamWriter swTempAclResult = null;
        static string tempResultPath = "";

        static void WriteLog(string info)
        {
            //Console.WriteLine(info);
            if (swTempAclResult != null)
            {
                swTempAclResult.WriteLine(info);
            }
        }

        static long ConvertDateTimeToInt(DateTime time)
        {
            DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new DateTime(1970, 1, 1, 0, 0, 0, 0));
            long t = (time.Ticks - startTime.Ticks) / 10000000;  
            return t;
        }

        static void Main(string[] args)
        {
            string filterCanbe = "user|group|ou|computer|server|policy|all|admin|controller|pc";
            if (args.Length != 4 && args.Length != 5)
            {
                Console.WriteLine(string.Format("adaclscan.exe DomainController Domain username password [{0}]", filterCanbe));
                Console.WriteLine("adaclscan.exe DomainController Domain username password [ldap filter]");
                Console.WriteLine("ldap filter example:");
                Console.WriteLine("  \"(&(objectcategory=computer)(operatingSystem=*2019*))\"");
                Console.WriteLine("  \"(&(objectcategory=computer)(servicePrincipalName=ldap*))\"");
                Console.WriteLine("  \"(&(objectcategory=computer)(servicePrincipalName=MSSQLSvc*))\"");
                Console.WriteLine("  \"(&(cn=*Admin*))\"");
                Console.WriteLine("  \"(&(cn=DoAdmin*))\"");
                Console.WriteLine("  \"(&(sAMAccountName=*Admin*))\"");
                Console.WriteLine("  \"(&(memberOf=CN=Domain Admins,CN=Users,DC=test,DC=com))\"");
                Console.WriteLine("  \"(&(memberOf=CN=Account Operators,CN=Builtin,DC=test,DC=com))\"");
                Console.WriteLine("");
                Console.WriteLine("filter syntax: https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx");
                Console.WriteLine("get all sid:");
                Console.WriteLine("  dsquery * -s 10.10.10.10 -u jerry -p Abcd1234 -limit 0 -attr objectsid distinguishedName");
                Console.WriteLine("  AdFind -h 10.10.10.10 -u jerry -up Abcd1234 -alldc+ objectSid sAMAccountName");
                return;
            }
            String DomainController = args[0];
            String Domain = args[1];
            String username = args[2]; //域用户名
            String password = args[3]; //域用户密码

            string myfilter = "(";
            if (args.Length == 5)
            {
                if (args[4] == "user")
                {
                    myfilter += "(&((&(objectCategory=person)(objectClass=user)))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
                }
                else if (args[4] == "group")
                {
                    myfilter += "((objectCategory=group))";
                }
                else if (args[4] == "ou")
                {
                    myfilter += "((objectCategory=organizationalUnit))";
                }
                else if (args[4] == "controller")
                {
                    myfilter += "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
                }
                else if (args[4] == "computer")
                {
                    myfilter += "((objectCategory=computer))";
                }
                else if (args[4] == "pc")
                {
                    myfilter += "(&(objectCategory=computer)(!(operatingSystem=*2008*))(!(operatingSystem=*2012*))(!(operatingSystem=*2016*))(!(operatingSystem=*2019*))(!(operatingSystem=*2022*)))";
                }
                else if (args[4] == "server")
                {
                    myfilter += "(|(operatingSystem=*2008*)(operatingSystem=*2012*)(operatingSystem=*2016*)(operatingSystem=*2019*)(operatingSystem=*2022*))";
                }
                else if (args[4] == "policy")
                {
                    myfilter += "(|(objectCategory=groupPolicyContainer)(objectClass=trustedDomain))";
                }
                else if (args[4] == "admin")
                {
                    myfilter += "(admincount=1)";
                }
            }
            if (args.Length == 4 || (args.Length == 5 && args[4] == "all"))
            {
                myfilter += "(objectCategory=*)";
            }
            myfilter += ")";
            if (args.Length == 5 && !filterCanbe.Split('|').Contains(args[4]))
            {
                Console.WriteLine("your cusom filter: " + args[4]); 
                myfilter = "(" + args[4] + ")";
            }

            Simulation.Run(Domain, username, password, () =>
            {
                int countObject = 0;
                
                DirectorySearcher searcher = Ldapcoon.getSearch(Domain, DomainController, false, false);
                SearchResultCollection result = Ldapcoon.LdapSearchAll(myfilter);
                StreamWriter sw_sidmap = new StreamWriter("map_sid_dn.txt");
                tempResultPath = string.Format("acl_result_temp_{0}.txt", ConvertDateTimeToInt(DateTime.Now));
                swTempAclResult = new StreamWriter(tempResultPath);
                foreach (SearchResult r in result)
                {
                    countObject += 1;
                    if (countObject % 1000 == 0)
                    {
                        Console.WriteLine(string.Format("Get Object Count: {0}", countObject));
                    }
                    string sid = "";
                    string distinguishedName = "";
                    string adspath = "";
                    if (r.Properties.Contains("distinguishedName"))
                    {
                        distinguishedName = r.Properties["distinguishedName"][0].ToString();
                    }
                    if (distinguishedName == "")
                    {
                        continue;
                    }
                    if (r.Properties.Contains("objectSid"))
                    {
                        SecurityIdentifier sido = new SecurityIdentifier(r.Properties["objectSid"][0] as byte[], 0);
                        sid = sido.Value.ToString();
                        mapSid_DN[sid] = distinguishedName;
                        sw_sidmap.WriteLine(sid + " " + distinguishedName);
                    }                    
                    if (r.Properties.Contains("adspath"))
                    {
                        adspath = r.Properties["adspath"][0].ToString();
                        mapDN_Path[distinguishedName] = adspath;
                    }
                    if (r.Properties.Contains("ntsecuritydescriptor"))
                    {
                        var sdbytes = (byte[])r.Properties["ntsecuritydescriptor"][0];
                        ActiveDirectorySecurity sd = new ActiveDirectorySecurity();
                        sd.SetSecurityDescriptorBinaryForm(sdbytes);

                        //直接再内存中处理，可能内存太大导致崩溃
                        //改为先输出到文件，最后都从文件来构造
                        WriteLog(distinguishedName);
                        PrintAllowPermissions(sd);
                        WriteLog("");
                        
                    }
                }
                Console.WriteLine(string.Format("Get Object Count: {0}", countObject));

                sw_sidmap.Close();
                swTempAclResult.Close();
                swTempAclResult = null;

                //从文件中再读取出来，组装结果
                string newResultPath = string.Format("acl_result_{0}.txt", ConvertDateTimeToInt(DateTime.Now));
                StreamWriter swNewResult = new StreamWriter(newResultPath);

                using (FileStream fs = File.Open(tempResultPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BufferedStream bs = new BufferedStream(fs))
                using (StreamReader sr = new StreamReader(bs))
                {
                    string line;
                    List<string> templines = new List<string>();
                    while ((line = sr.ReadLine()) != null)
                    {
                        //新的对象
                        if (line.Length > 1 && line[0] != ' ')
                        {
                            if (templines.Count() >= 2)
                            {
                                templines.ForEach(swNewResult.WriteLine);
                            }
                            templines.Clear();
                            swNewResult.WriteLine(line);
                            continue;
                        }
                        //新的权限
                        if (line.Contains(":"))
                        {
                            //有数据才打印
                            if (templines.Count() >= 2) {
                                templines.ForEach(swNewResult.WriteLine);
                            }
                            templines.Clear();
                            if (line.Contains(":"))
                            {
                                templines.Add(line);
                            }                            
                        }
                        if (line.StartsWith("    S-1-5-21"))
                        {
                            string sid = line.Replace(" ", "");
                            string tempdn = GetUserSidString(sid);
                            if (tempdn.StartsWith("CN=Domain Admins,CN=Users,") ||
                                tempdn.StartsWith("CN=Administrators,CN=Builtin,") ||
                                tempdn.StartsWith("CN=Enterprise Admins,CN=Users,") ||
                                tempdn.StartsWith("CN=Enterprise Key Admins,CN=Users,") ||
                                tempdn.StartsWith("CN=Key Admins,CN=Users,") ||
                                tempdn.StartsWith("CN=Exchange Servers,OU=Microsoft Exchange Security Groups,") ||
                                tempdn.StartsWith("CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,") ||
                                tempdn.StartsWith("CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,") ||
                                tempdn.StartsWith("CN=Organization Management,OU=Microsoft Exchange Security Groups,") ||
                                tempdn.StartsWith("CN=Terminal Server License Servers,CN=Builtin,") ||
                                //可以关注这2个特殊的组
                                tempdn.StartsWith("CN=Account Operators,CN=Builtin,") ||
                                tempdn.StartsWith("CN=Cert Publishers,CN=Users,")
                                )
                            {
                                continue;
                            }
                            templines.Add("    " + tempdn);
                            //swNewResult.WriteLine("    "+tempdn);
                        }
                        else if (line.StartsWith("    "))
                        {
                            templines.Add(line);
                            //swNewResult.WriteLine(line);
                        }
                    }
                    //输出最后剩余的信息
                    if (templines.Count() >= 2)
                    {
                        templines.ForEach(swNewResult.WriteLine);
                    }
                    templines.Clear();
                }
                swNewResult.Close();
                //删除临时的文件
                File.Delete(tempResultPath);
            });

        }

        static string GetUserSidString(string sid)
        {
            if (mapSid_DN.ContainsKey(sid))
            {
                return mapSid_DN[sid].ToString();
            }
            return sid;
        }
        static void PrintAllowPermissions(ActiveDirectorySecurity sd)
        {
            var ownerSid = sd.GetOwner(typeof(SecurityIdentifier));  
            var allExtendedRightsPrincipals = new HashSet<string>();
            var fullControlPrincipals = new HashSet<string>();
            var writeOwnerPrincipals = new HashSet<string>();
            var writeDaclPrincipals = new HashSet<string>();
            var writePropertyPrincipals = new HashSet<string>();
            var genericWritePrincipals = new HashSet<string>();
            var dcSyncPrincipals1 = new HashSet<string>();      
            var dcSyncPrincipals2 = new HashSet<string>();
            var userForceChangePassword = new HashSet<string>();

            var rules = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                if ($"{rule.AccessControlType}" != "Allow")
                {
                    continue;
                }
                var sid = rule.IdentityReference.ToString();
                if (sid.Split('-').Length <= 5)
                {
                    continue;
                }
                string guid = rule.ObjectType.ToString();
                
                string tempdn = GetUserSidString(sid);
                if (tempdn.StartsWith("CN=Domain Admins,CN=Users,") ||
                    tempdn.StartsWith("CN=Administrators,CN=Builtin,") ||
                    tempdn.StartsWith("CN=Enterprise Admins,CN=Users,") ||
                    tempdn.StartsWith("CN=Enterprise Key Admins,CN=Users,") ||
                    tempdn.StartsWith("CN=Key Admins,CN=Users,") ||
                    tempdn.StartsWith("CN=Exchange Servers,OU=Microsoft Exchange Security Groups,") ||
                    tempdn.StartsWith("CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,") ||
                    tempdn.StartsWith("CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,") ||
                    tempdn.StartsWith("CN=Organization Management,OU=Microsoft Exchange Security Groups,") ||
                    tempdn.StartsWith("CN=Terminal Server License Servers,CN=Builtin,") ||
                    //可以关注这2个特殊的组
                    tempdn.StartsWith("CN=Account Operators,CN=Builtin,") ||
                    tempdn.StartsWith("CN=Cert Publishers,CN=Users,")
                    )
                {
                    continue;
                }
                if (guid.ToLower() == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
                {
                    dcSyncPrincipals1.Add(tempdn);
                }
                if (guid.ToLower() == "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
                {
                    dcSyncPrincipals2.Add(tempdn);
                }
                //00299570-246d-11d0-a768-00aa006e0529 User-Force-Change-Password Reset Password
                if (guid.ToLower() == "00299570-246d-11d0-a768-00aa006e0529")
                {
                    userForceChangePassword.Add(tempdn);
                }

                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                {
                    allExtendedRightsPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                {
                    fullControlPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                {
                    writeOwnerPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                {
                    writeDaclPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty)
                {
                    writePropertyPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                {
                    genericWritePrincipals.Add(tempdn);
                }
                /*
                Delete = 0x10000,
                ReadControl = 0x20000,
                WriteDacl = 0x40000,
                WriteOwner = 0x80000,
                Synchronize = 0x100000,
                AccessSystemSecurity = 0x1000000,
                GenericRead = 0x20094,
                GenericWrite = 0x20028,
                GenericExecute = 0x20004,
                GenericAll = 0xF01FF,
                CreateChild = 0x1,
                DeleteChild = 0x2,
                ListChildren = 0x4,
                Self = 0x8,
                ReadProperty = 0x10,
                WriteProperty = 0x20,
                DeleteTree = 0x40,
                ListObject = 0x80,
                ExtendedRight = 0x100
                 */
            }

            if (fullControlPrincipals.Count > 0)
            {
                WriteLog("  GenericAll:");
                fullControlPrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    WriteLog("    " + p);
                });
            }

            if (writeOwnerPrincipals.Count > 0)
            {
                WriteLog("  WriteOwner:");
                writeOwnerPrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    WriteLog("    " + p);
                });
            }

            if (writeDaclPrincipals.Count > 0)
            {
                WriteLog("  WriteDacl:");
                writeDaclPrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    WriteLog("    " + p);
                });
            }

            if (writePropertyPrincipals.Count > 0)
            {
                WriteLog("  WriteProperty:");
                writePropertyPrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    WriteLog("    " + p);
                });
            }

            if (genericWritePrincipals.Count > 0)
            {
                WriteLog("  GenericWrite:");
                genericWritePrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    WriteLog("    " + p);
                });
            }

            //求交集
            dcSyncPrincipals1.IntersectWith(dcSyncPrincipals2);
            if (dcSyncPrincipals1.Count > 0)
            {
                WriteLog("  Dcsync:");
                dcSyncPrincipals1.OrderBy(p => p).ToList().ForEach(p => {
                    WriteLog("    " + p);
                });
            }

            if (userForceChangePassword.Count> 0)
            {
                WriteLog("  ResetPassword:");
                genericWritePrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    WriteLog("    " + p);
                });
            }
        }


    }
}