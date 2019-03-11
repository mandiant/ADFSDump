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
            Console.WriteLine("\r\n");
        }

        public static void ShowHelp()
        {
            string Help = @"
ADFSDump

Dump all sorts of AD FS related goodies.

Arguments:
    /domain: The FQDN of the domain
    /server: The FQDN of the domain controller to connect to

Requirements:
    Must be run locally on an AD FS server. Preferably the primary
    Assumes that AD FS is configured to use WID rather than a dedicated SQL server
    Must be run using the AD FS service account
";
            Console.WriteLine(Help);
        }
    }

}
