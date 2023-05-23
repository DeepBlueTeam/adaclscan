using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace adaclscan
{
    internal class Simulation
    {
        //参考：https://github.com/dev-2null/ADCollector
        public static void Run(string domain, string username, string password, Action action)
        {
            using (var accessToken = GetUserAccessToken(domain, username, password))
            {
                WindowsIdentity.RunImpersonated(accessToken, action); //作为模拟 Windows 标识运行指定操作
            }
        }

        internal static SafeAccessTokenHandle GetUserAccessToken(string domain, string username, string password)
        {
            const int LOGON32_PROVIDER_DEFAULT = 0;
            const int LOGON32_LOGON_NETONLY = 9;

            bool isLogonSuccessful = Api.LogonUser(username, domain, password, LOGON32_LOGON_NETONLY, LOGON32_PROVIDER_DEFAULT, out var safeAccessTokenHandle);
            if (!isLogonSuccessful)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return safeAccessTokenHandle;
        }
    }
}
