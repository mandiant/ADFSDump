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

        public string GetSignInProtocol()
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
            string baseMsg = $@"
{Name}
 ==================
    Enabled: {IsEnabled}
    Sign-In Protocol: {GetSignInProtocol()}
    Sign-In Endpoint: {FederationEndpoint}
    Signature Algorithm: {SignatureAlgorithm}
    Identity: {Identity}
    Access Policy: {AccessPolicy}
    
    Issuance Rules: {IssuanceRules}";
            if (!string.IsNullOrEmpty(EncryptionCert))
            {
                string encryption = $"Encryption Certificate: {EncryptionCert}\r\n\r\n";
                baseMsg += encryption;
            }
            if (!string.IsNullOrEmpty(AuthRules))
            {
                string auth = $"Authorization Rules: {AuthRules}\r\n\r\n";
                baseMsg += auth;
            }
            if (!string.IsNullOrEmpty(ActAsAuthRules))
            {
                string actAsAuth = $"ActAs Authorization Rules: {ActAsAuthRules}\r\n\r\n";
                baseMsg += actAsAuth;
            }
            if (!string.IsNullOrEmpty(OnBehalfAuthRules))
            {
                string onBehalf = $"OnBehalf Authorization Rules: {OnBehalfAuthRules}\r\n\r\n";
                baseMsg += onBehalf;
            }
            if (!string.IsNullOrEmpty(StrongAuthRules))
            {
                string strongAuth = $"StrongAuth Authorization Rules: {StrongAuthRules}\r\n\r\n";
                baseMsg += strongAuth;
            }
            return baseMsg;
        }
    }
}
