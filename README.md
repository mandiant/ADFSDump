# ADFSDump

A C# tool to dump all sorts of goodies from AD FS.

Created by Doug Bienstock [(@doughsec)](https://twitter.com/doughsec) while at Mandiant FireEye.

This tool is designed to be run in conjunction with ADFSpoof. ADFSdump will output all of the information needed in order to generate security tokens using ADFSpoof.

## Detailed Description

ADFSDump is a tool that will read information from Active Directory and from the AD FS Configuration Database that is needed to generate forged security tokens. This information can then be fed into ADFSpoof to generate those tokens. 

### Requirements

* ADFSDump must be run under the user context of the AD FS service account. You can get this information by running a process listing on the AD FS server or from the output of the `Get-ADFSProperties` cmdlet. Only the AD FS service account has the permissions needed to access the configuration database. Not even a DA can access this.
* ADFSDump assumes that the service is configured to use the Windows Internal Database (WID). Although it would be trivial to support an external SQL server, this feature does not exist right now.
* ADFSDump must be run locally on an AD FS server, NOT an AD FS web application proxy. The WID can only be accessed locally via a named pipe.

### What this tool will do

* Query Active Directory to find the current DKM key and output it to STDOUT
* Query the AD FS Configuration database for the EncryptedPFX blob for the Token Signing key/cert pair and output it to STDOUT
* Query the AD FS Configuration database for all of the configured federated applications (relying parties) and output important information about them such as the RP Identifier, Signature algorithm, token encryption certificate, issuance rules, access control rules and more. This is all output to STDOUT


## Usage

* `/domain:`: The Active Directory domain to target. Defaults to the current domain.
* `/server:`: The Domain Controller to target. Defaults to the current DC.
* `/nokey`: Switch. Toggle to disable outputting the DKM key.
* `/database`:  (optional) SQL connection string if ADFS is using remote MS SQL rather than WID. Wrap in quotes, i.e. "/database:Data Source=sql.domain.com;Initial Catalog=AdfsConfigurationV4;Integrated Security=True"
* `/username`: (optional) Username to run the tool as. If set, must have a password passed with it.
* `/password`: (optional) Password for the user account to run the tool as.

## Compilation Instructions

A compiled version will not be released. You'll have to compile it yourself!

 ADFSDump was built against .NET 4.5 with Visual Studio 2017 Community Edition. Simply open up the project .sln, choose "Release", and build.

### Targeting Other .NET Versions

ADFSDump's default build configuration is for .NET 4.5, which will fail on systems without that version installed. To target ADFSDump for .NET 4 or 3.5, open the .sln solution, go to Project -> ADFSDump Properties and change the "Target framework" to another version.

Note that AD FS requires .NET framework 4.5, so I'm not sure why you need to use a different version anyway :wink: