using System;
using ADFSDump.ReadDB;
using System.Collections.Generic;
using ADFSDump.RelyingPartyTrust;
using ADFSDump.About;
using ADFSDump.ActiveDirectory;

namespace ADFSDump
{
    
    class Program
    {
        private static Dictionary<string, string> ParseArgs(string[] args)
        {
            Dictionary<string, string> arguments = new Dictionary<string, string>();
            try
            {
                foreach(string argument in args)
                {
                    var index = argument.IndexOf(":", StringComparison.Ordinal);
                    if (index > 0)
                    {
                        arguments[argument.Substring(0, index)] = argument.Substring(index + 1);
                    }
                    else
                    {
                        arguments[argument] = "";
                    }
                }
            } catch (Exception)
            {
               Info.ShowHelp();
               Environment.Exit(1);
            }
            return arguments;
        }

        static void Main(string[] args)
        {
            Info.ShowInfo();

            Dictionary<string, string> arguments = null;
            if (args.Length > 0) arguments = ParseArgs(args);

            if (!arguments.ContainsKey("/nokey"))
            {
                ADSearcher.GetPrivKey(arguments);
            }
            

            Dictionary<string, RelyingParty>.ValueCollection rps = DatabaseReader.ReadConfigurationDb();
            if (rps == null)
            {
                Environment.Exit(1);
            }
            foreach(var relyingparty in rps)
            {
                Console.WriteLine($"[-] {relyingparty}");
            }

        }
    }
}
