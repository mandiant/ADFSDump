using System;

namespace ADFSDump.About
{
    public static class Info
    {
        public static void ShowInfo()
        {
            Console.WriteLine("    ___    ____  ___________ ____                      ");
            Console.WriteLine("   /   |  / __ \\/ ____/ ___// __ \\__  ______ ___  ____ ");
            Console.WriteLine("  / /| | / / / / /_   \\__ \\/ / / / / / / __ `__ \\/ __ \\");
            Console.WriteLine(" / ___ |/ /_/ / __/  ___/ / /_/ / /_/ / / / / / / /_/ /");
            Console.WriteLine("/_/  |_/_____/_/    /____/_____/\\__,_/_/ /_/ /_/ .___/ ");
            Console.WriteLine("                                              /_/      ");
            Console.WriteLine("Created by @doughsec");
            Console.WriteLine("\r\n");
        }

        public static void ShowHelp()
        {
            string Help = @"
ADFSDump

Dump all sorts of AD FS related goodies.

By default ADFSDump will do three things:
1) Query Active Directory for the DKM container and output the decryption key to STDOUT
2) Query the AD FS Configuration Database and print out the EncryptedPFX blob for the token signing certificate and private key to STDOUT
3) Query the AD FS Configuration Database for the configured relying party trusts and print out pertinent information needed to craft a token for it and print it all to STDOUT

Arguments:
    /domain: The FQDN of the domain, defaults to the current domain
    /server: The FQDN of the domain controller to connect to, defaults to current
    /nokey: (optional) Flag. Disable fetching of DKM key from AD

Requirements:
    Supports AD FS 2012 and 2016
    Must be run locally on an AD FS server. Preferably the primary
    Assumes that AD FS is configured to use WID rather than a dedicated SQL server
    Must be run using the AD FS service account
";
            Console.WriteLine(Help);
        }
    }

}
