# setupFed.py script
This script will setup the neccessary artifacts for a SAML federation between two providers.
Currently only OCI IAM is supported for the Service Provider (SP) and Identity Provider (IdP).

The script has two flags '-sp' and '-idp {oci,azure,okta}'.  It will create artifacts for both SP and IdP. You can run the script in a single tenancy with two differnt domains representing the SP and IdP. You achieve this by adding both the -sp and -idp flags. However, a more common use case is to run this in two seperate tenancies.

Artifact created for SP
  1. Identity Provider - Using the provided IdPs metadata URL or File
  2. Confidential Application - Used with IdP's Generic SCIM Application
  3. Bucket/Object Store - To store the SP data for the IdP script (step 2)
  4. A pre-authentiated request (PAR) - To be used when configuring the IdP

Artifacts created for IdP
  1. Generic SCIP Application - Used to push user/group data to SP
  2. SAML Application - Configured to accept request from SP

In order for the IdP to acccess the data from the SP, the script will generate a pre-authenticated request (PAR) with the -sp flag. This PAR is required when running the script with the -idp flag for access to SP metadata.  It us up to the SP admin to send the PAR in a timely mannner to the IdP admininstrator.

After cloing the repo in your environment,  you need to copy or move the myCOnfig.cfg.template to myConfig.cfg.

Then run the command 'python setupFed.py -sp'.  The SP artifacts must be created first since a PAR is required for the IdP configuration.

Running the script in CloudShell, please be aware that by default the OCI Config file is stored in /etc/.oci/config and the delegated tokem is used.   For this reason the script has three additional flags: 
-cf : Location of the config file. If not specified will use default location.
-ca : The authentication type (delegated token, instance principal, secure token and default)
-cp : The profile name. If not specified will use the [DEFAULT] profile name.

Use the approprate config flags when needed based on your environment.
