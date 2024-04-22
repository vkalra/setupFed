
"""
This should be one script with 2 steps:
    from SP
        select domain
        provide IdP's URL
        Note: SAML metadata is published at /fed/v1/metadata on both sides
        Create Identity Provider using IdPs metadata
        Create and activate App for SCIM provisioning - Create Confidential App and store the client ID and secret
        provide or create bucket
            Create file in Object Store with the above
            Create a PAR for that
        Output PAR URL
    from IdP
        select domain
        select group
        provide URL to PAR
        Create App for SAML federation -  SAML APP
        Create App for SCIM provisioning - Create Generic SCIM - Client Credential App
The script should have a check / dry run step and then an execute step.
"""
import oci
import configparser
import argparse
import requests
import os
from  datetime import datetime
from datetime import timedelta

import http.client as http_client
import logging

logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
http_client.HTTPConnection.debuglevel = 1

# Public URIs for OCI providers
OCI_METADATA_URI = "/fed/v1/metadata/"
ASSERTION_CONSUMER_URL = "/fed/v1/sp/sso"
REST_API_ENDPOINT = "/admin/v1"

# OCI App Roles
USER_ADMIN_ROLE = "User Administrator"
DEFAULT_SCOPE = "urn:opc:idm:__myscopes__"

# App Names for OCI Apps
CONFIDENTIAL_APP_NAME = "Confidential App For IDP "
IDENTITY_PROVIDER_NAME = "OCI Identity Provder"
SCIM_APP_NAME = "Generic SCIM App to OCI SP"
SAML_APP_NAME = "SAML App for OCI SP"
DESCRIPTION = "This application was created by the setupFed.py script on " + datetime.now().strftime("%m/%d/%Y %H:%M:%S")

# Provider Types
SP = 'OCI_Service_Provider'
OCI_IDP = 'OCI_Identity_Provider'

# Initialize the SP data file;
#  this file will be sent to
#  the IdP
SP_DATA_FILE = 'spData.cfg'
spData = configparser.ConfigParser()
spData[SP] = {}

# Read the script config file.
CONFIG_FILE = 'myConfig.cfg'
myConfig = configparser.ConfigParser()
try:
    with open(CONFIG_FILE,'r') as f:
      myConfig.read_file(f)
except FileNotFoundError as ex:
    print(CONFIG_FILE + " file not found.")
    raise SystemExit
myConfig.read(CONFIG_FILE)


# Setup argument parser and get profile
parser = argparse.ArgumentParser(prog='setupFed',
                                 description='This script will configure a SAML Partner (IdP/SP). Use the -sp and -idp flags if there both are in the same tenancy.',
                                 epilog='')
parser.add_argument('-idp',
                    help="Setup up a SAML Identity Provider.",
                    action='store', choices=['oci','azure','okta'])
parser.add_argument('-sp',
                    help="Setup a SAML Service Provider on OCI->Identity Domain",
                    action='store_true')
parser.add_argument('-ca', default='default',
                    help="Select the OCI config authenticate type (delegated, instance principal, secure token or default)",
                    action='store', choices=['dt','ip','st','default'] )
parser.add_argument('-cp', default="", dest='config_profile',
                    help="Select the OCI config profile name if none is specified use default",
                    action='store')
parser.add_argument('-cf', default="", dest='file_location',
                    help="Select the OCI config file location if none is specified use default location.",
                    action='store')
args = parser.parse_args()

# Setup OCI Config
# Credit to MAP Compliance Checker script
# Github ....

# if instance principals authentications
if args.ca == 'ip':
    try:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        ociConfig = {'region': signer.region, 'tenancy': signer.tenancy_id}
    
    except Exception:
            print("Error obtaining instance principals certificate, aborting")
            raise SystemExit

# -----------------------------
# Delegation Token
# -----------------------------
elif args.ca == 'dt':
    try:
        # check if env variables OCI_CONFIG_FILE, OCI_CONFIG_PROFILE exist and use them
        env_config_file = os.environ.get('OCI_CONFIG_FILE')
        env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

        # check if file exist
        if env_config_file is None or env_config_section is None:
            print(
                "*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
            print("")
            raise SystemExit

        ociConfig = oci.config.from_file(env_config_file, env_config_section)
        delegation_token_location = ociConfig["delegation_token_file"]

        with open(delegation_token_location, 'r') as delegation_token_file:
            delegation_token = delegation_token_file.read().strip()
            # get signer from delegation token
            signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
                delegation_token=delegation_token)

    except KeyError:
        print("* Key Error obtaining delegation_token_file")
        raise SystemExit

    except Exception:
        raise
# ---------------------------------------------------------------------------
# Security Token - Credit to Dave Knot (https://github.com/dns-prefetch)
# ---------------------------------------------------------------------------
elif args.ca == 'st':
    try:
        # Read the token file from the security_token_file parameter of the .config file
        ociConfig = oci.config.from_file(
            oci.config.DEFAULT_LOCATION,
            (args.config_profile if args.config_profile else oci.config.DEFAULT_PROFILE)
            )

        token_file = ociConfig['security_token_file']
        token = None
        with open(token_file, 'r') as f:
            token = f.read()

        # Read the private key specified by the .config file.
        private_key = oci.signer.load_private_key_from_file(ociConfig['key_file'])

        signer = oci.auth.signers.SecurityTokenSigner(token, private_key)

    except KeyError:
        print("* Key Error obtaining security_token_file")
        raise SystemExit

    except Exception:
        raise
# -----------------------------
# config file authentication
# -----------------------------
else:
    try:
        ociConfig = oci.config.from_file(
            args.file_location if args.file_location else oci.config.DEFAULT_LOCATION,
            (args.config_profile if args.config_profile else oci.config.DEFAULT_PROFILE)
            )
        signer = oci.signer.Signer(
            tenancy=ociConfig["tenancy"],
            user=ociConfig["user"],
            fingerprint=ociConfig["fingerprint"],
            private_key_file_location=ociConfig.get("key_file"),
            pass_phrase=oci.config.get_config_value_or_default(
                ociConfig, "pass_phrase"),
            private_key_content=ociConfig.get("key_content")
            )
        
    except Exception:
        print(
            f'** OCI Config was not found here : {oci.config.DEFAULT_LOCATION} or env varibles missing, aborting **')
        raise SystemExit


def save_config_file(config, configFile):
        try:
            with open(configFile, 'w') as cf:
                config.write(cf)
        except (IOError, OSError):
            print("Error writing to file")
            raise SystemExit

def send_request(url, with_signer=True):
    try:
        if with_signer:
            response  = requests.get(url,auth=signer)
        else:
            response  = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        if err.response.status_code == 401:
            raise
        else:
            print("An error occurred:", err)
    return response

def get_metadata(url, provider):
     print("Getting Metadata for " + provider + "...")
     # For now get  the metadata from the URL
     # TODO: In order for this to work the access client
     #  flag needs to be on.  Check if this can be done
     #  via the SDK
     # TODO: Look for SKD call to get the metadata
     # TODO Add exception handling for request and write
     
     try:
        response  = send_request(url,False)
        file_name = provider + "-metadata.xml"
        with open(file_name, 'wb') as fd:
            fd.write(response.content)
        fd.close()
     except requests.exceptions.RequestException as err:
        if err.response.status_code == 401:
            print(err)
            if provider == OCI_IDP:
                print("Possible Cause: Please verify that the Identity Provider Domain has seleted the Access Signing Certificate checkbox in Settings->Doamain Settings ")
            raise SystemExit
     except (IOError, OSError):
        print("Error writing to file: " + file_name)
        raise SystemExit
     
         
    #TODO trap a 401 error from send reqest and note that
    # that it could be because of the checkbox in the domain for 
    # access certificate.

def get_metadata_from_par(parRequest):
    print("Getting Metadata from PAR " + parRequest + "...")
    # Get the SP metadata file and the Client id and secret from PAR Request
    # Extract the bucket name from the PAR
    bucketName = parRequest.split("/b/")[1].split("/o/")[0]
    files  = send_request(parRequest)
    print("BucketName = ", bucketName)
    print("files in PAR = ", files.json())

    #Get files from Bucket
    #TODO check if the par is valid ..the next line will fail if it is
    for item in files.json()['objects']:
        print("file: ", item['name'])
        file = send_request(parRequest + item['name'])
    
        try:
            with open(item['name'], 'wb') as fd:
                fd.write(file.content)
            fd.close()  
        except (IOError, OSError):
            print("Error writing to file")
            raise SystemExit

def create_metadata_bucket(compartment, type):
    print("Creating/Updating Bucket and Pre-Authenicated Request (PAR)...")
        
    # Initialize service client with default config file
    object_storage_client = oci.object_storage.ObjectStorageClient(ociConfig)

    try:
        bucketResponse = object_storage_client.create_bucket(
        namespace_name=myConfig[type]['bucket_namespace'],
        create_bucket_details=oci.object_storage.models.CreateBucketDetails(
        name=myConfig[type]['bucket_name'],
        compartment_id=compartment,  
        public_access_type="ObjectReadWithoutList",
        storage_tier="Standard",
        object_events_enabled=False,
        versioning="Enabled",
        auto_tiering="Disabled"))
    except oci.exceptions.ServiceError as err:
        #print(e.status)
        if err.status == 409:
            print("Status Code 409 (doplicate) : Bucket already exists.")
            #Ask if bucket can be updated otherwise exit
            if (user_input("Shall I update the bucket (Y/n)", None, None)) != 'Y':
                print("Run the script again with new bucket name.  Exiting...")
                raise SystemExit
        else:
            print("Error Creatinbg Bucket: " + err)
            exit(0)
        
    #print(bucketResponse.data)

    # Create PAR
    try:
        parResponse = object_storage_client.create_preauthenticated_request(
            namespace_name=myConfig[type]['bucket_namespace'],
            bucket_name= myConfig[type]['bucket_name'],
            create_preauthenticated_request_details=oci.object_storage.models.CreatePreauthenticatedRequestDetails(
            name=myConfig[type]['bucket_name'] + "PAR",
            access_type="AnyObjectRead",
            time_expires=datetime.now() + timedelta(days=1),
            bucket_listing_action="ListObjects"))
    
        #print(parResponse.data)
        myConfig[type]['par_request'] = parResponse.data.full_path
        print ("The PAR reqest is: " + parResponse.data.full_path)
        print ("Send the PAR request to the IdP administrator to access SP data.")
        save_config_file(myConfig, CONFIG_FILE)

    except oci.exceptions.ServiceError as err:
        print("Error Creating PAR: " + err)
        raise SystemExit

    # Read SP metdata file
    try:
        obj = open(type + '-metadata.xml', "r")

        objectResponse = object_storage_client.put_object(
            namespace_name=myConfig[type]['bucket_namespace'],
            bucket_name= myConfig[type]['bucket_name'],
            object_name=obj.name,
            put_object_body = obj.read())

        obj.close()

        #print(objectResponse.data)
    except oci.exceptions.ServiceError as err:
            print("Error Creating Object: " + err)
            raise SystemExit

    # Send the required data to onject storage.
    # This will be consumed by the IdP (SCIM App)
    spData[SP]['host'] = myConfig[SP]['idurl'].split(":443/")[0]
    spData[SP]['baseuri'] = REST_API_ENDPOINT
    spData[SP]['client_id'] = myConfig[SP]['client_id']
    spData[SP]['client_secret'] = myConfig[SP]['client_secret']
    spData[SP]['scope'] = DEFAULT_SCOPE
    spData[SP]['asertion_consumer_url'] = myConfig[SP]['idurl'] + ASSERTION_CONSUMER_URL

    save_config_file(spData,SP_DATA_FILE)

    try:
        obj = open(SP_DATA_FILE, "r")

        objectResponse = object_storage_client.put_object(
            namespace_name=myConfig[type]['bucket_namespace'],
            bucket_name=myConfig[type]['bucket_name'],
            object_name=obj.name,
         put_object_body = obj.read())

        obj.close()

        #print(objectResponse.data)
    except oci.exceptions.ServiceError as err:
        print("Error Creating Object: " + err)
        raise SystemExit
    
def create_saml_app(endpoint):
    print("Creating SAML Applicaiont for OCI Identity Provider...")
   
    # Get/Read Metadata for SP
    #getMetadata(myConfig[SP]['idurl'] + OCI_METADATA_URI, SP)
    mdf = open(SP + '-metadata.xml', "r")

    try:
        # Initialize service client with default config file
        domainClient = oci.identity_domains.IdentityDomainsClient(ociConfig, endpoint)

        # Send the request to service, some parameters are not required, see API
        # doc for more info
        create_app_response = domainClient.create_app(
            app=oci.identity_domains.models.App(
                schemas = ["urn:ietf:params:scim:schemas:oracle:idcs:App",
                          "urn:ietf:params:scim:schemas:oracle:idcs:extension:samlServiceProvider:App"],
                display_name=SAML_APP_NAME,
                compartment_ocid=myConfig[SP]['compartment_ocid'],
                tenancy_ocid=myConfig[SP]['tenancy_ocid'],
                active=True,
                trust_scope = "Explicit",
                description=DESCRIPTION,
                urn_ietf_params_scim_schemas_oracle_idcs_extension_saml_service_provider_app =oci.identity_domains.models.AppExtensionSamlServiceProviderApp(
                    metadata = mdf.read(),
                    #TODO get the ACU from the metadata. or enter in mnaully
                    assertion_consumer_url=spData[SP]['idurl'] + ASSERTION_CONSUMER_URL
                    # Need to enter the assertion consumnerr URL
                ),
                based_on_template=oci.identity_domains.models.AppBasedOnTemplate(
                    value="CustomSAMLAppTemplateId",
                    ref=None,
                    well_known_id="CustomSAMLAppTemplateId")
            )
        )
        # Get the data from response
        #print(create_app_response.data)

        # Get a list of groups annd select which group you want for Grantee
        grantees = (myConfig[OCI_IDP]['groups']).split(',')
        #print(grantees)

        # For every gtoup you need to add the grantee
        for  grant in grantees:
            create_grant_response = domainClient.create_grant(
                grant=oci.identity_domains.models.Grant(
                    schemas=["urn:ietf:params:scim:schemas:oracle:idcs:Grant"],
                    grant_mechanism="ADMINISTRATOR_TO_GROUP",
                    grantee=oci.identity_domains.models.GrantGrantee(
                        value=grant,
                        type="Group"
                    ),
                app=oci.identity_domains.models.GrantApp(
                    value=create_app_response.data.id,
                ),
                #entitlement=oci.identity_domains.models.GrantEntitlement(
                #attribute_name="appRoles",
                #attribute_value=UAid)
                    )
                )
            #print(create_grant_response)
    except oci.exceptions.ServiceError as err:
        if err.status == 409:
            print("Status Code 409 (doplicate) : Application already exists.  Continuing....")
        else:
            print("Error Creating SAML APP: " + err)
            raise SystemExit

def create_confidential_app(endpoint):
    print("Creating Confidential Application and store the client ID and secret...")
    try:
        domainClient = oci.identity_domains.IdentityDomainsClient(ociConfig, endpoint)

        # Get thei list of App Roles 
        # we are looking got User Administrator role
        app_role_response = domainClient.list_app_roles(filter="app.value eq \"IDCSAppId\"")

        # Get the ID for User Administrator
        UAid = None
        for resource in app_role_response.data.resources:
            #print (resource.display_name)
            if resource.display_name == USER_ADMIN_ROLE:
                UAid = resource.id
                #print ("The Resource is: " + resource.id)
                # TODO if we do not find the UA role, exit? or log?  This should never happen
                #print("The USid is: " + UAid)
        
        create_app_response = domainClient.create_app(app=oci.identity_domains.models.App(
                schemas = ["urn:ietf:params:scim:schemas:oracle:idcs:App"],
                display_name=CONFIDENTIAL_APP_NAME,
                compartment_ocid=myConfig[SP]['compartment_ocid'],
                tenancy_ocid=myConfig[SP]['tenancy_ocid'],
                client_type="confidential",
                active=True,
                allowed_grants=["client_credentials"],
                is_login_target=True,
                is_o_auth_client=True,
                trust_scope = "Explicit",
                show_in_my_apps=True,
                description=DESCRIPTION,
                based_on_template=oci.identity_domains.models.AppBasedOnTemplate(
                    value="CustomWebAppTemplateId",
                    ref=None,
                    #last_modified="EXAMPLE-lastModified-Value",
                    well_known_id="CustomWebAppTemplateId")))
    
        # Get the id of the newly created app
        #print("The APP ID is: " + create_app_response.data.id)
        myConfig[SP]['app_id'] = create_app_response.data.id
            
        create_grant_response = domainClient.create_grant(
        grant=oci.identity_domains.models.Grant(
            schemas=["urn:ietf:params:scim:schemas:oracle:idcs:Grant"],
            grant_mechanism="ADMINISTRATOR_TO_APP",
            grantee=oci.identity_domains.models.GrantGrantee(
                value=create_app_response.data.id,
                type="App"
                #ref=None,
                #display="Confidential App for OCI-IDP - V2"
                ),
            app=oci.identity_domains.models.GrantApp(
                value="IDCSAppId",
                #ref=None,
                #display="EXAMPLE-display-Value"
                ),
            entitlement=oci.identity_domains.models.GrantEntitlement(
                attribute_name="appRoles",
                attribute_value=UAid)
                )
            )
        #print(create_grant_response.data)
        
        # Store the clientID and Secret
        myConfig[SP]['client_id'] = create_app_response.data.name
        myConfig[SP]['client_secret'] = create_app_response.data.client_secret

        save_config_file(myConfig, CONFIG_FILE)

    except oci.exceptions.ServiceError as err:
        if err.status == 409:
            print(err)
            print("Status Code 409 (doplicate) : Application already exists.  Continuing....")
            # Edge Case: Check if app_id exists otherwise exit
            if myConfig.get(SP,'app_id') == '': 
                print ("app_id is missing. Try deleting the Confidential App and run the script again.")
                raise SystemExit 
            # Get the client ID and secret and save it
            # So as to run again (re-entrant)
            get_app_response = domainClient.get_app(
                app_id=myConfig[SP]['app_id'])
            #print(get_app_response.data)
            # Store the clientID and Secret
            myConfig[SP]['client_id'] = get_app_response.data.name
            myConfig[SP]['client_secret'] = get_app_response.data.client_secret
            save_config_file(myConfig, CONFIG_FILE)
        else:
            print("Error Creating Confidential APP: " + err)
            raise SystemExit
            
def create_generic_scim_app(endpoint):
    print("Creating SCIM Application for provisioing users to Serivr Provider...")
   
    #response = sendRequest(endpoint + "/admin/v1/AppTemplates?filter=name+co+%22SCIM%22")
    #print(response.content)
    #print(domainClient.get_app(app_id="07de5c07edfe42a785eb328fabef1d28").data)
    
    # The seeded teamplate ID for Generic SCIM App - Cleint credentials
    template_id = "df61971610a531f48a3187b90c97573c"
    
    try:
        # Initialize service client with default config file
        domainClient = oci.identity_domains.IdentityDomainsClient(ociConfig, endpoint)

        # Send the request to service, some parameters are not required, see API
        # doc for more info
        create_app_response = domainClient.create_app(app=oci.identity_domains.models.App(
                schemas = ["urn:ietf:params:scim:schemas:oracle:idcs:App"],
                          # "urn:ietf:params:scim:schemas:oracle:idcs:extension:managedapp:app"],
                display_name=SCIM_APP_NAME,
                compartment_ocid=myConfig[SP]['compartment_ocid'],
                tenancy_ocid=myConfig[SP]['tenancy_ocid'],
                active=True,
                is_managed_app = True,
                #allowed_grants=["client_credentials"],
                #is_login_target=True,
                #is_o_auth_client=True,
                trust_scope = "Explicit",
                #show_in_my_apps=True,
                description=DESCRIPTION,
                urn_ietf_params_scim_schemas_oracle_idcs_extension_managedapp_app=oci.identity_domains.models.AppExtensionManagedappApp(
                    account_form_visible = True,
                    enable_sync=True,
                    admin_consent_granted= True,
                    connected= True
                ),
                based_on_template=oci.identity_domains.models.AppBasedOnTemplate(
                    value=template_id,
                    ref=None,
                    well_known_id=template_id)))
        
        #Get the app id for the patch app call
        #print(create_app_response.data.id)
        myConfig[OCI_IDP]['app_id'] = create_app_response.data.id
        save_config_file(myConfig, CONFIG_FILE)

    except oci.exceptions.ServiceError as err:
        if err.status == 409:
            print("Status Code 409 (doplicate) : Application already exists.  Continuing....")
            # Edge Case: Check if app_id exists otherwise exit
            if not(myConfig.has_option(OCI_IDP,'app_id')):
                print ("app_id is missing. Try deleting the SCIM app and run the script again.")
                raise SystemExit 
        else:
            print("Error updating Generic SCOM Application.")
            print(err)
            raise SystemExit
       
    print("Updating SCIM Application for provisioing users to Serivr Provider...")
    try:
        # Use patch_app and pass JSON data to complete creation of app.
        patch_app_response = domainClient.patch_app(
            app_id=myConfig[OCI_IDP]['app_id'] ,
            #authorization="EXAMPLE-authorization-Value",
            #resource_type_schema_version="EXAMPLE-resourceTypeSchemaVersion-Value",
            #attributes="EXAMPLE-attributes-Value",
            #attribute_sets=["request"],
            patch_op=oci.identity_domains.models.PatchOp(
                schemas=["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                operations=[
                    oci.identity_domains.models.Operations(
                        op="REPLACE",
                        path="urn:ietf:params:scim:schemas:oracle:idcs:extension:managedapp:App:bundleConfigurationProperties[name eq \"host\"].value",
                        value=[spData[SP]['host']]),
                    oci.identity_domains.models.Operations(
                    op="REPLACE",
                        path="urn:ietf:params:scim:schemas:oracle:idcs:extension:managedapp:App:bundleConfigurationProperties[name eq \"baseuri\"].value",
                        value=[spData[SP]['baseuri']]),
                    oci.identity_domains.models.Operations(
                        op="REPLACE",
                        path="urn:ietf:params:scim:schemas:oracle:idcs:extension:managedapp:App:bundleConfigurationProperties[name eq \"clientid\"].value",
                        value=[spData[SP]['client_id']]),
                    oci.identity_domains.models.Operations(
                        op="REPLACE",
                        path="urn:ietf:params:scim:schemas:oracle:idcs:extension:managedapp:App:bundleConfigurationProperties[name eq \"clientsecret\"].value",
                        value=[spData[SP]['client_secret']]),
                    oci.identity_domains.models.Operations(
                        op="REPLACE",
                        path="urn:ietf:params:scim:schemas:oracle:idcs:extension:managedapp:App:bundleConfigurationProperties[name eq \"scope\"].value",
                        value=[spData[SP]['scope']]),
                    oci.identity_domains.models.Operations(
                        op="REPLACE",
                        path="urn:ietf:params:scim:schemas:oracle:idcs:extension:managedapp:App:bundleConfigurationProperties[name eq \"authenticationServerUrl\"].value",
                        value=[spData[SP]['asertion_consumer_url']]
                        )]))
            #if_match="EXAMPLE-ifMatch-Value",
            #opc_retry_token="EXAMPLE-opcRetryToken-Value")
    
    # Get the data from response
    #print(create_app_response.data)
    except oci.exceptions.ServiceError as err:
        if err.status == 409:
            print("Status Code 409 (doplicate) : Application already exists.  Continuing....")
            print(err)
        else:
            print("Error updating Generic SCOM Applcation.")
            print(err)
            raise SystemExit

        #  if not display the values to fill in for provisoiing
        """
        print("To complete the setup please Enable Provisioning for this applicaion and provide the following:")
        print("Host Name: " + spConfig[SP]['idurl'].split(":443/")[0] )
        print("Base URI: " + REST_API_ENDPOINT)
        print("Client ID: " + spConfig[SP]['client_id'])
        print("Client  Secret: " + spConfig[SP]['client_secret'])
        print("Scope: " +  "urn:opc:idm:__myscopes__")
        print("AuthenticatoinServer URL: " + spConfig[SP]['idurl'] + ASSERTION_CONSUMER_URL)
        """
    print("     To complete the setup schedule to sync users to Service Provider (in the console)")
    print("     The default attribute mappings should be fine, if not make changes as needed.")
          
def create_identity_provider(endpoint, idpMetadata):
    print("Configuring an Identity Provider within your Service Provider...")

    # RAW DATA SAMPLE
    # {"partnerName":"trest1","metadata":"","signatureHashAlgorithm":"SHA-256","userMappingMethod":"NameIDToUserAttribute","userMappingStoreAttribute":"userName","nameIdFormat":"saml-none","enabled":false,"schemas":["urn:ietf:params:scim:schemas:oracle:idcs:IdentityProvider"]}
    # Initialize service client with default config file
    
    try:
        domainClient = oci.identity_domains.IdentityDomainsClient(ociConfig, endpoint)
        
        # Read metadate for IdP
        mdf = open(idpMetadata, "r")
       
        # Send the request to service, some parameters are not required, see API
        # doc for more info
        response = domainClient.create_identity_provider(
            identity_provider=oci.identity_domains.models.IdentityProvider(
                schemas=["urn:ietf:params:scim:schemas:oracle:idcs:IdentityProvider"],
                partner_name=IDENTITY_PROVIDER_NAME,
                enabled=True,
                compartment_ocid=myConfig[SP]['compartment_ocid'],
                tenancy_ocid=myConfig[SP]['tenancy_ocid'],
                description=DESCRIPTION,
                metadata=mdf.read(),
                user_mapping_method="NameIDToUserAttribute",
                user_mapping_store_attribute="userName",
                #assertion_attribute="EXAMPLE-assertionAttribute-Value",
                signature_hash_algorithm="SHA-256",
                name_id_format="saml-none"))
        #print(response.data)
    except oci.exceptions.ServiceError as err:
        if err.status == 409:
            print("Status Code 409 (doplicate) : Provider already exists.  Continuing....")
        else:
            print("Error Creating Identity Provider: " + err)
            raise SystemExit

def setup_idp_domain():
    print("Seting up the Identity Provider Domain...")
    
    # Get the metadata for IDP domain
    get_metadata_from_par(myConfig[OCI_IDP]['par_request'])

    # Create a new configParser for data from SP and pass down
    spData.read(SP_DATA_FILE)

    create_generic_scim_app(myConfig[OCI_IDP]['idurl'])
    create_saml_app(myConfig[OCI_IDP]['idurl'])

def setup_sp_domain():
    print("Seting up the Service Provider Domain...")

    # Get the metadata for IDP domain
    if myConfig[SP]['idp_type'.upper()] == 'OCI':
        #Check the idp_method, if URL then get metadatta
        if myConfig[SP]['idp_method'.upper()] == 'URL':
            get_metadata(myConfig[SP]['idp_metadata'],OCI_IDP)
            create_identity_provider(myConfig[SP]['idurl'],OCI_IDP + '-metadata.xml')
        else:
            create_identity_provider(myConfig[SP]['idurl'],myConfig[SP]['idp_metadata'])

        create_confidential_app(myConfig[SP]['idurl'])
    else:
        print('Identity Provider type not supported')
    
    # Save the SP metadata to a file
    get_metadata(myConfig[SP]['idurl'] + OCI_METADATA_URI,SP)

    create_metadata_bucket(myConfig[SP]['compartment_ocid'], SP)
    
def user_input(question, config, provider, type='string'):
    """
    """
    response = None
    if config != None:
        questionValue = question + " [Current: " + myConfig[provider][config]+ "]"
        response = input(questionValue)
        #print ("RESPONSE IS: " + response)
        if response:
            myConfig[provider][config] = response
        else:
            response =  myConfig[provider][config]
    else:
        if type == 'int':
            while True:
                response = input(question)
                if response.isdigit():
                    break
                else:
                    print("Please enter an interger. \n")
        else:
            response = input(question)
    return response

def get_inputs(provider):
    """
    """
    # Question needed for provider
    Q1 = "Enter the Tenancy Name:"
    Q2 = "Enter the Tenancy OCID:"
    Q3 = "Enter the Compartment OCID: "
    Q4 = "Select the Identity Domain for your " + provider + ":"
    Q5 = "Enter the URL for the Service Provider Metadata:"
    Q6 = "Enter the IdP type[OCI, Azure, Okta]:"
    Q61 = "Enter the IdP metadata format [File or URL]:"
    Q611 = "Enter the URL for the Identity Provider Metadata:"
    Q612 = "Enter the file name for the Identity Provider Metadata:"
    Q7 = "Select group(s) for access for the " + provider + "(Entter '0' to exit):"
    Q8 = "Enter the Bucket Namespce(This is usually the tenancy name):"
    Q9 = "Enter the Bucket Name (no spaces):" 
    Q10 = "Enter the PAR request form the Service Provider?"
    QCONT = "Wish to continue? (Y|n)"

    if provider == SP:
        # Reset
        myConfig[SP]['client_id']='client_id_TBD'
        myConfig[SP]['client_secret']='client_secret_TBD'
        myConfig[SP]['par_request']= "par_request_TBD"
        print("Answer the following questions for your OCI Service Provider:\n")
    else:
        if provider == OCI_IDP:
            print("Answer the following questions for your OCI Identity Provider:\n")
        else:
            print("Identity Provider type " + provider + " does not exist or supported")
            return False

    user_input(Q1,'tenancy_name', provider)
    user_input(Q2,'tenancy_ocid', provider)
    user_input(Q3,'compartment_ocid',provider)

    # Get list of identity domains and select
    # TODO - Trap 401 errros, this is usuall because
    #  it could not find valid admin in oci config.
    #  Need to add some of the -0f flags suring starup
    identity = oci.identity.IdentityClient(ociConfig)
    domains = identity.list_domains(myConfig[provider]['compartment_ocid']).data
    
    # List the domains and allow the Admin to select
    print("Identity Domains found...")
    count = 0
    for domain in domains:
        count +=1
        print(str(count) + ")" + domain.display_name)
        print("  " + domain.url)
        print("  " + domain.id + "\n")
    option = user_input(Q4,None,None,'int')
    while True:
        if 1 <= int(option) <= count:
            myConfig[provider]['idDomain'] =  domains[int(option)-1].id 
            myConfig[provider]['idName'] = domains[int(option)-1].display_name
            myConfig[provider]['idURL'] = domains[int(option)-1].url
            break
        else:
            print("Out of range. Please pick again.\n")
            option = user_input(Q4,None,None,'int')

    if provider == SP:
        user_input(Q6,'idp_type',SP)
        while True:
            method = user_input(Q61,'idp_method', SP)
            if method.lower() == "file":
                user_input(Q612,'idp_metadata',SP)
                break
            if method.lower() == "url":
                user_input(Q611,'idp_metadata',SP)
                break
        user_input(Q8,'bucket_namespace',SP)
        user_input(Q9,'bucket_name',SP)
        
    if provider == OCI_IDP:
       # userInput(Q5,'sp_metadata_url', OCI_IDP)

        # Initialize service client with default config file
        domainClient = oci.identity_domains.IdentityDomainsClient(ociConfig, myConfig[OCI_IDP]['idurl'])

        # Select group(s) for this application
        #TODO: Pagination not working - file bug.
        #myGroups = oci.pagination.list_call_get_all_results(domainClient.list_groups)

        # TODO: how too send only display name and id
        # There is a bug that return other attriburtes with null
        list_group_response = domainClient.list_groups(
            sort_order="ASCENDING",
            attributes = "display_name,id",
        )
        #print(list_group_response.data)

        print("Select the group(s) to allow authentication for the Identoty Provider.")
        groups = list_group_response.data.resources
        #TODO: Support manual pagination 
        count = 0
        for group in groups:
            count +=1
            print(str(count) + ")" + group.display_name)
            #print("  " + group.id + "\n")

        myConfig[OCI_IDP]['groups'] = ""
        while True:
            option = user_input(Q7,None,None,'int')
            if option == '0':
                break
            if 1<= int(option) <= count:
                if myConfig[OCI_IDP]['groups'] == "":
                    myConfig[OCI_IDP]['groups'] +=  groups[int(option)-1].id
                else:
                    myConfig[OCI_IDP]['groups'] +=  "," +  groups[int(option)-1].id
            else:
                print("Please choose a number between 1 and " + str(count) + ".")

        user_input(Q10,'par_request', OCI_IDP)

    print("\nYou entered: \n")
    for config in myConfig[provider]:
        print(config + ": " + myConfig[provider][config] + "\n")

    if (user_input(QCONT, None, None)) == 'Y':
        save_config_file(myConfig, CONFIG_FILE)
        return True
    return False
    
def main():

    if args.sp == False and args.idp == None:
        parser.print_help()
        exit(0)

    if args.sp:
        if get_inputs(SP):
            setup_sp_domain()
            print("Service Provider setup complete!")

    if args.idp == 'oci':
        if get_inputs(OCI_IDP):
            setup_idp_domain()
            print("Identity Provider setup complete!")
    
    if args.idp != None and args.idp !='oci':
        print("IDP NOT SUPPORTED YET")

    return None

if __name__ == "__main__":
        main()