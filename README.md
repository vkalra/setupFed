# setupFed.py script
This script will setup the neccessary artifacts for a SAML federation between two entities.
Currently only OCI IAM is supported for the Service Provider (SP) and Identity Provider (IdP).

The script has two flags '-sp' and '-idp {oci,azure,okta}'.  It will create artifacts for both SP and IdP.  You can run the script in a single tenancy with two differnt domains representing the SP and IdP or more likely you will run the script in two seperate tenancies.

Artifact created for SP
  1. Identity Provider (using provided IdPs metadata URL)
  2. Confidential Application used with IdP's Generic SCIM Application
  3. Bucket/Object Store - To store the SP data for the IdP script
  4. A pre-authentiated request (PAR) to be used when configuring the IdP.

Artifacts created for IdP
  1. Generic SCIP Application - Used to push user data to SP
  2. SAML Application - Configured to accept request from SP

In order for the IdP to acccess the data from the SP, the script will generate a pre-authenticated request (PAR) with the -sp flag. THis PAR is required when running the script with the -idp flag for access to SP metadata.  It us up to the SP admin to send the PAR in a timely mannner.
