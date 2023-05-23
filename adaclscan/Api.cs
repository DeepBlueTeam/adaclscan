using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static adaclscan.Struct;

namespace adaclscan
{
    internal class Api
    {
        //https://www.pinvoke.net/default.aspx

        [DllImport("netapi32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern int I_NetServerPasswordSet2(
            string PrimaryName,
            string AccountName,
            ref NETLOGON_SECURE_CHANNEL_TYPE AccountType,
            string ComputerName,
            ref NETLOGON_AUTHENTICATOR Authenticator,
            out NETLOGON_AUTHENTICATOR ReturnAuthenticator,
            ref NL_TRUST_PASSWORD ClearNewPassword
            );

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetGetJoinInformation(string server, out IntPtr domain, out NetJoinStatus status);

        [DllImport("Netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("netapi32.dll", SetLastError = true)]
        public static extern int NetSessionEnum(
             [In, MarshalAs(UnmanagedType.LPWStr)] string ServerName,
             [In, MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
             [In, MarshalAs(UnmanagedType.LPWStr)] string UserName,
             Int32 Level,
             out IntPtr bufptr,
             int prefmaxlen,
             ref Int32 entriesread,
             ref Int32 totalentries,
             ref Int32 resume_handle);

        [DllImport("ADVAPI32.DLL", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out SafeAccessTokenHandle phToken);


        [DllImport("netapi32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern int I_NetServerReqChallenge(
            string PrimaryName,
            string ComputerName,
            ref NETLOGON_CREDENTIAL ClientChallenge,
            ref NETLOGON_CREDENTIAL ServerChallenge
            );

        [DllImport("netapi32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern int I_NetServerAuthenticate2(
            string PrimaryName,
            string AccountName,
            NETLOGON_SECURE_CHANNEL_TYPE AccountType,
            string ComputerName,
            ref NETLOGON_CREDENTIAL ClientCredential,
            ref NETLOGON_CREDENTIAL ServerCredential,
            ref ulong NegotiateFlags
            );

        [DllImport("netapi32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern int I_NetServerPasswordSet2(
            string PrimaryName,
            string AccountName,
            NETLOGON_SECURE_CHANNEL_TYPE AccountType,
            string ComputerName,
            ref NETLOGON_AUTHENTICATOR Authenticator,
            out NETLOGON_AUTHENTICATOR ReturnAuthenticator,
            ref NL_TRUST_PASSWORD ClearNewPassword
            );

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtect(
           IntPtr lpAddress,
           uint dwSize,
           uint flNewProtect,
           out uint lpflOldProtect
        );

        [DllImport("kernel32.dll")]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] lpBuffer, uint dwSize, ref int lpNumberOfBytesRead);


        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);


        [DllImport("Netapi32.dll")]
        public extern static uint NetLocalGroupGetMembers([MarshalAs(UnmanagedType.LPWStr)] string servername, [MarshalAs(UnmanagedType.LPWStr)] string localgroupname, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, out IntPtr resumehandle);


        [DllImport("Netapi32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern uint DsEnumerateDomainTrusts(string ServerName,
                            uint Flags,
                            out IntPtr Domains,
                            out uint DomainCount);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetShareEnum(
                                         string ServerName,
                                         int level,
                                         ref IntPtr bufPtr,
                                         uint prefmaxlen,
                                         ref int entriesread,
                                         ref int totalentries,
                                         ref int resume_handle
                                         );


        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetWkstaUserEnum(
           string servername,
           int level,
           out IntPtr bufptr,
           int prefmaxlen,
           out int entriesread,
           out int totalentries,
           ref int resume_handle);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoExW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern Int32 RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr identity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoExW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, ref SEC_WINNT_AUTH_IDENTITY AuthIdentity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);


        [DllImport("Rpcrt4.dll", EntryPoint = "RtlInitUnicodeString", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("Rpcrt4.dll", EntryPoint = "I_RpcBindingInqSecurityContext", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern Int32 I_RpcBindingInqSecurityContext(IntPtr Binding, out IntPtr SecurityContextHandle);

        [DllImport("SSPICLI.DLL", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern Int32 QueryContextAttributes(IntPtr hContext, uint ulAttribute, ref SecPkgContext_SessionKey pContextAttributes);



        [DllImport("ntdll.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern Int32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern UInt32 NetrServerReqChallenge(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr ComputerName, IntPtr ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern UInt32 NetrServerAuthenticate3(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr AccountName, NETLOGON_SECURE_CHANNEL_TYPE SecoureChannelType, IntPtr ComputerName, IntPtr ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge, out uint NegotiateFlags, out uint AccountRid);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern UInt32 NetServerPasswordSet2(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, IntPtr ComputerName, IntPtr Authenticator, IntPtr ReturnAuthenticator, IntPtr ClearNewPassword);


        [DllImport("Rpcrt4.dll", EntryPoint = "RpcEpResolveBinding", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern Int32 RpcEpResolveBinding(IntPtr Binding, IntPtr IfSpec);


        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern Int32 RpcBindingFree(ref IntPtr lpString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern Int32 RpcStringBindingCompose(
            String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options,
            out IntPtr lpBindingString
            );

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        public static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);


        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        internal static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, UInt32 OptionValue);


        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
                CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr Handle);


      
    }
}
