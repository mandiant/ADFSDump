using System;
using ADFSDump.ReadDB;
using System.Collections.Generic;
using ADFSDump.RelyingPartyTrust;
using ADFSDump.About;
using ADFSDump.ActiveDirectory;

namespace ADFSDump
{
    
    public class Program
    {
        private static Dictionary<string, string> ParseArgs(string[] args)
        {
            Dictionary<string, string> arguments = new Dictionary<string, string>();
            try
            {
                foreach(string argument in args)
                {
                    var index = argument.IndexOf(":");
                    if (index > 0)
                    {
                        arguments[argument.Substring(0, index)] = argument.Substring(index + 1);
                    }
                }
            } catch (Exception e)
            {
                Console.WriteLine(string.Format("!!! Exception parsing args: {0}", e));
            }
            return arguments;
        }

        static void Main(string[] args)
        {
            Info.ShowInfo();

            Dictionary<string, string> arguments = null;
            if (args.Length > 0)
            {
                arguments = ParseArgs(args);
            }
            

            ADSearcher.GetPrivKey(arguments);

            
            Dictionary<string, RelyingParty>.ValueCollection rps = DatabaseReader.ReadConfigurationDB();
            if (rps == null)
            {
                System.Environment.Exit(1);
            }
            foreach(var relyingparty in rps)
            {
                Console.WriteLine(string.Format("[-] {0}", relyingparty));
            }

        }
    }
}
