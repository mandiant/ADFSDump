using System;

namespace ADFSDump.RelyingPartyTrust
{
    public class RelyingParty
    {
        public string Id
        { get; set; }

        public string Name
        { get; set; }

        public bool IsWsFed
        { get; set; }

        public bool IsSaml
        { get; set; }

        public string FederationEndpoint
        { get; set; }

        public bool IsEnabled
        { get; set; }

        public string SignatureAlgorithm
        { get; set; }

        public string AccessPolicy
        { get; set; }

        public string Identity
        { get; set; }

        public string EncryptionCert
        { get; set; }

        public string IssuanceRules
        { get; set; }

        public string AuthRules
        { get; set; }

        public string ActAsAuthRules
        { get; set; }

        public string OnBehalfAuthRules
        { get; set; }

        public string StrongAuthRules
        { get; set; }

        public string getSignInProtocol()
        {
            if (IsSaml)
            {
                return "SAML 2.0";
            }
            else if (IsWsFed)
            {
                return "WsFed-SAML (SAML 1.1)";
            }
            else
            {
                return "Unknown";
            }
        }

        public override string ToString()
        {
            string baseMsg = string.Format(@"
{0}
 ==================
    Enabled: {1}
    Sign-In Protocol: {2}
    Sign-In Endpoint: {3}
    Signature Algorithm: {4}
    Identity: {5}
    Acess Policy: {6}
    
    Issuance Rules: {7}", Name, IsEnabled, getSignInProtocol(), FederationEndpoint, SignatureAlgorithm, Identity, AccessPolicy, IssuanceRules);
            if (!string.IsNullOrEmpty(EncryptionCert))
            {
                string encryption = string.Format("Encryption Certificate: {0}\r\n\r\n", EncryptionCert);
                baseMsg += encryption;
            }
            if (!string.IsNullOrEmpty(AuthRules))
            {
                string auth = string.Format("Authorization Rules: {0}\r\n\r\n", AuthRules);
                baseMsg += auth;
            }
            if (!string.IsNullOrEmpty(ActAsAuthRules))
            {
                string actAsAuth = string.Format("ActAs Authorization Rules: {0}\r\n\r\n", ActAsAuthRules);
                baseMsg += actAsAuth;
            }
            if (!string.IsNullOrEmpty(OnBehalfAuthRules))
            {
                string onBehalf = string.Format("OnBehalf Authorization Rules: {0}\r\n\r\n", OnBehalfAuthRules);
                baseMsg += onBehalf;
            }
            if (!string.IsNullOrEmpty(StrongAuthRules))
            {
                string strongAuth = string.Format("StrongAuth Authorization Rules: {0}\r\n\r\n", StrongAuthRules);
                baseMsg += strongAuth;
            }
            return baseMsg;
        }
    }
}
