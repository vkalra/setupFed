
"""
This should be one script with 2 steps:
    from SP
        select domain
        provide IdP's URL
        Note: SAML metadata is published at /fed/v1/metadata on both sides
        Create Identity Provider using IdPs metadata
        Create and activate App for SCIM provisioning - Create Confidential App and store the clioent ID and secret
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
from xml.etree import ElementTree as ET
from  datetime import datetime
from datetime import timedelta
from oci.signer import Signer
import http.client as http_client
import logging

logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
http_client.HTTPConnection.debuglevel = 1

# Get the DEFAULT OCI profile
ociConfig = oci.config.from_file()
identity = oci.identity.IdentityClient(ociConfig)

# Get the Signer for raw requests from .oci/config
auth = Signer(
    tenancy=ociConfig['tenancy'],
    user=ociConfig['user'],
    fingerprint=ociConfig['fingerprint'],
    private_key_file_location=ociConfig['key_file'],
    pass_phrase=ociConfig['pass_phrase']
)
# Public URIs for OCI providers
OCI_METADATA_URI = "/fed/v1/metadata/"
ASSERTION_CONSUMER_URL = "/fed/v1/sp/sso"
REST_API_ENDPOINT = "/admin/v1"

# OCI App Roles
USER_ADMIN_ROLE = "User Administrator"

# App Names for OCI Apps
CONFIDENTIAL_APP_NAME = "Confidential App For IDP "
IDENTITY_PROVIDER_NAME = "OCI Identity Provder"
SCIM_APP_NAME = "Generic SCIM App to OCI SP"
SAML_APP_NAME = "SAML App for OCI SP"
DESCRIPTION = "This application was created by the setupFed.py script on " + datetime.now().strftime("%m/%d/%Y %H:%M:%S")

# Provider Types
SP = 'OCI_Service_Provider'
OCI_IDP = 'OCI_Identity_Provider'

# Read the config for IdP/SP
CONFIG_FILE = 'myConfig.cfg'
myConfig = configparser.ConfigParser()
myConfig.read(CONFIG_FILE)
spConfig = configparser.ConfigParser()

# Setup argument parser and get profile
parser = argparse.ArgumentParser(prog='setupFed',
                                 description='This script will configure a SAML Partner (IdP/SP). Use the -sp and -idp flags if there both are in the same tenancy.',
                                 epilog='')

parser.add_argument('-idp',
                    help="Setup up a SAML Identity Provider.",
                    action='store', choices=['oci','azure','okta'])
parser.add_argument('-sp',
                    help="Setup up a SAML Service Provider on OCI->Identity Domain",
                    action='store_true')
args = parser.parse_args()


def sendRequest(url):
    try:
        response  = requests.get(url,auth=auth)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)

    return response

def getMetadata(url, provider):
     print("Getting Metadata for " + provider + "...")
     # For now get  the metadata from the URL
     # TODO: In order for this to work the access client
     #  flag needs to be on.  Check if this can be done
     #  via the SDK
     # TODO: Look for SKD call to get the metadata
     # TODO Add exception handling for request and write
     
     response  = sendRequest(url)
     try:
        with open(provider + "-metadata.xml", 'wb') as fd:
            fd.write(response.content)
        fd.close()
     except (IOError, OSError):
        print("Error writing to file")

def getMetadataFromPar(parRequest):
    # Get the SP metadata file and the Client id and secret from PAR Request
    # Extract the bucket name from the PAR
    bucketName = parRequest.split("/b/")[1].split("/o/")[0]
    files  = sendRequest(parRequest)
    print("BucketName = ", bucketName)
    print("files in PAR = ", files.json())

    #Get files from Bucket
    #TODO chek if the par is valid ..the next line will fail if it is
    for item in files.json()['objects']:
        print("file: ", item['name'])
        file = sendRequest(parRequest + item['name'])
    
        try:
            with open(item['name'], 'wb') as fd:
                fd.write(file.content)
            fd.close()  
        except (IOError, OSError):
            print("Error writing to file")
  
    return None

def createMetadataBucket(compartment, type):
    print("Creating/Updating Bucket and Pre-Authenicated Request (PAR)...")
    if myConfig.has_option(type,'bucket_name') != True:
        BUCKET_NAME = "SP_BUCKET"
        myConfig[type]['bucket_name'] = BUCKET_NAME
    else:
        BUCKET_NAME = myConfig[type]['bucket_name']
        
    # Initialize service client with default config file
    object_storage_client = oci.object_storage.ObjectStorageClient(ociConfig)

    if myConfig.has_option(type,'bucket_ocid') != True:
        # Send the request to service, some parameters are not required, see API
        # doc for more info
        try:
            bucketResponse = object_storage_client.create_bucket(
            namespace_name=myConfig[type]['bucket_namespace'],
            create_bucket_details=oci.object_storage.models.CreateBucketDetails(
            name=BUCKET_NAME,
            compartment_id=compartment,  
            public_access_type="ObjectReadWithoutList",
            storage_tier="Standard",
            object_events_enabled=False,
            versioning="Enabled",
            auto_tiering="Disabled"))
        except oci.exceptions.ServiceError as err:
            #print(e.status)
            if err.status == 409:
                print("Status Code 409 (doplicate) : Bucket already exists.  Continuing....")
            else:
                print(err)
        
        #print(bucketResponse.data)

    #print(metadataResponse.data)

    # Create PAR
    try:
        parResponse = object_storage_client.create_preauthenticated_request(
            namespace_name=myConfig[type]['bucket_namespace'],
            bucket_name=BUCKET_NAME,
            create_preauthenticated_request_details=oci.object_storage.models.CreatePreauthenticatedRequestDetails(
            name=BUCKET_NAME + "PAR",
            access_type="AnyObjectRead",
            time_expires=datetime.now() + timedelta(days=1),
            bucket_listing_action="ListObjects"))
    
        print(parResponse.data)
        myConfig[type]['par_request'] = parResponse.data.full_path
        #myConfig[type]['parID'] = parResponse.data.id

        # Save the configuration
        try:
            with open(CONFIG_FILE, 'w') as configfile:
                myConfig.write(configfile) 
        except (IOError, OSError):
            print("Error writing to file")
        
        
    except oci.exceptions.ServiceError as e:
        print(e)

    # Read SP metdata file
    try:
        obj = open(type + '-metadata.xml', "r")

        objectResponse = object_storage_client.put_object(
            namespace_name=myConfig[type]['bucket_namespace'],
            bucket_name=BUCKET_NAME,
            object_name=obj.name + ".for_idp",
            put_object_body = obj.read())

        obj.close()

        #print(objectResponse.data)
    except oci.exceptions.ServiceError as e:
            print(e)

    #TODO Store data for the idp provisoiing app abd client id and secret
    # Currently passing the entire myCOnfig.cfg to bucket
    try:
        obj = open(CONFIG_FILE, "r")

        objectResponse = object_storage_client.put_object(
            namespace_name=myConfig[type]['bucket_namespace'],
            bucket_name=BUCKET_NAME,
            object_name=obj.name + ".for_idp",
         put_object_body = obj.read())

        obj.close()

        #print(objectResponse.data)
    except oci.exceptions.ServiceError as e:
        print(e)
    
def createSAMLApp(endpoint):
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
                    assertion_consumer_url=spConfig[SP]['idurl'] + ASSERTION_CONSUMER_URL
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

def createConfidentialApp(endpoint):
    # Create Confidential App and save the CLiennt ID and Secret
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

        # Save the configuration
        try:
            with open(CONFIG_FILE, 'w') as configfile:
                myConfig.write(configfile) 
        except (IOError, OSError):
            print("Error writing to file")
    
    except oci.exceptions.ServiceError as err:
        if err.status == 409:
            print("Status Code 409 (doplicate) : Application already exists.  Continuing....")
            #TODO get the client ID and secret and save it
            # So as to run again (re-entrant)
        else:
            print(err)

def createGenericSCIMApp(endpoint):
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
                    admin_consent_granted= True,
                    enable_sync=True,
                    bundle_configuration_properties=[
                        oci.identity_domains.models.AppBundleConfigurationProperties(
                            confidential=False,
                            display_name= "Host Name",
                            help_message= "The host name of your application's SCIM REST API endpoints.",
                            icf_type="String",
                            name="host",
                            order=1,
                            required=True,
                            value= [
                                "idcs-1fa3024a5c544b89a3b0b623819c7837.identity.oraclecloud.com"
                            ]
                        )
                    ]
                ),
                        #oci.identity_domains.models.AppBundleConfigurationProperties()
                        #{
                        #    "confidential":False,
                        #    "display_name": "Host Name",
                        #    "help_message": "The host name of your application's SCIM REST API endpoints.",
                        #    "icf_type":"String",
                        #    "name":"host",
                        #    "order":None,
                        #    "required":None,
                        #    "value": [
                        #        "idcs-1fa3024a5c544b89a3b0b623819c7837.identity.oraclecloud.com"
                        #    ]
                        #}
                based_on_template=oci.identity_domains.models.AppBasedOnTemplate(
                    value=template_id,
                    ref=None,
                    well_known_id=template_id)))
    
        # TODO - The app provisioing is not ebabled.  
        # Check to see if this can be done via SDK
        #  if not display the values to fill in for provisoiing
        print("To complete the setup please Enable Provisioning for this applicaion and provide the following:")
        print("Host Name: " + spConfig[SP]['idurl'].split(":443/")[0] )
        print("Base URI: " + REST_API_ENDPOINT)
        print("Client ID: " + spConfig[SP]['client_id'])
        print("Client  Secret: " + spConfig[SP]['client_secret'])
        print("Scope: " +  "urn:opc:idm:__myscopes__")
        print("AuthenticatoinServer URL: " + spConfig[SP]['idurl'] + ASSERTION_CONSUMER_URL)
        print("The default attribute mappings should be fine, if not make changes as needed.")
        
        # Get the data from response
        #print(create_app_response.data)
    except oci.exceptions.ServiceError as err:
        if err.status == 409:
            print("Status Code 409 (doplicate) : Application already exists.  Continuing....")
        else:
            print(err)

def createIdentityProvider(endpoint):
    print("Configuring an Identity Provider within your Service Provider...")

    # RAW DATA SAMPLE
    # {"partnerName":"trest1","metadata":"","signatureHashAlgorithm":"SHA-256","userMappingMethod":"NameIDToUserAttribute","userMappingStoreAttribute":"userName","nameIdFormat":"saml-none","enabled":false,"schemas":["urn:ietf:params:scim:schemas:oracle:idcs:IdentityProvider"]}
    # Initialize service client with default config file
    
    try:
        domainClient = oci.identity_domains.IdentityDomainsClient(ociConfig, endpoint)
        
        # Read metadate for IdP in same tenancy
        #if myConfig['DEFAULT']['idp_sp_in_same_tenancy'] == 'Y': 
        mdf = open(OCI_IDP + '-metadata.xml', "r")
       
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
            print(err)

def setupIDPDomain():
    print("Seting up the Identity Provider Domain...")
    
    # Get the metadata for IDP domain
    # TODO this URL will come from Bucket/Flat file
    getMetadataFromPar(myConfig[OCI_IDP]['par_request'])

    # Create a new configParser for data from SP and pass down
    spConfig.read('myConfig.cfg.for_idp')

    createGenericSCIMApp(myConfig[OCI_IDP]['idurl'])
    createSAMLApp(myConfig[OCI_IDP]['idurl'])

    #TODO - Get the SCIM provisioing details from the bucket and
    # show the values the admin needs to enter in

    return None

def setupSPDomain():
    print("Seting up the Service Provider Domain...")

    # Get the metadata for IDP domain
    if myConfig[SP]['idp_type'.upper()] == 'OCI':
        getMetadata(myConfig[SP]['idp_metadata_url'],OCI_IDP)
        # Create the Identit Provider and Confidential App
        createIdentityProvider(myConfig[SP]['idurl'])
        createConfidentialApp(myConfig[SP]['idurl'])
    else:
        print('Identity Provider type not supported')
    
    # Save the SP metadata to a file
    getMetadata(myConfig[SP]['idurl'] + OCI_METADATA_URI,SP)

    if myConfig.has_option(SP,'bucket_name') != True:
        createMetadataBucket(myConfig[SP]['compartment_ocid'], SP)
    else:
        print("The SAML data will be store in bucket: " + myConfig[SP]['bucket_name'])
        option = input("Do you wish to update data in this location(Y/n)? ")
        if option == 'Y':
            createMetadataBucket(myConfig[SP]['compartment_ocid'], SP)
        else:
            print("No bucket with metadata was updated,  You must namually send the data ro your IdO.")

def userInput(question, config, provider, type='string'):
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

def getInputs(provider):
    """
    """
    # Question needed for provider
    Q1 = "Enter the Tenancy Name:"
    Q2 = "Enter the Tenancy OCID:"
    Q3 = "Enter the Compartment OCID: "
    Q4 = "Select the Identity Domain for your " + provider + ":"
    Q5 = "Enter the URL for the Service Provider Metadata:"
    Q6 = "Enter the IdP type[OCI, Azure, Okta]:"
    Q61 = "Enter the URL for the Identity Provider Metadata:"
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

    userInput(Q1,'tenancy_name', provider)
    userInput(Q2,'tenancy_ocid', provider)
    userInput(Q3,'compartment_ocid',provider)

    # Get list of identity domains and select
    domains = identity.list_domains(myConfig[provider]['compartment_ocid']).data
    
    # List the domains and allow the Admin to select
    print("Identity Domains found...")
    count = 0
    for domain in domains:
        count +=1
        print(str(count) + ")" + domain.display_name)
        print("  " + domain.url)
        print("  " + domain.id + "\n")
    option = userInput(Q4,None,None,'int')
    while True:
        if 1 <= int(option) <= count:
            myConfig[provider]['idDomain'] =  domains[int(option)-1].id 
            myConfig[provider]['idName'] = domains[int(option)-1].display_name
            myConfig[provider]['idURL'] = domains[int(option)-1].url
            break
        else:
            print("Out of range. Please pick again.\n")
            option = userInput(Q4,None,None,'int')

    if provider == SP:
        userInput(Q6,'idp_type',SP)
        userInput(Q61,'idp_metadata_url',SP)
        userInput(Q8,'bucket_namespace',SP)
        userInput(Q9,'bucket_name',SP)
        
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
            option = userInput(Q7,None,None,'int')
            if option == '0':
                break
            if 1<= int(option) <= count:
                if myConfig[OCI_IDP]['groups'] == "":
                    myConfig[OCI_IDP]['groups'] +=  groups[int(option)-1].id
                else:
                    myConfig[OCI_IDP]['groups'] +=  "," +  groups[int(option)-1].id
            else:
                print("Please choose a number between 1 and " + str(count) + ".")

        userInput(Q10,'par_request', OCI_IDP)

    print("\nYou entered: \n")
    for config in myConfig[provider]:
        print(config + ": " + myConfig[provider][config] + "\n")

    if (userInput(QCONT, None, None)) == 'Y':
        # Save the configuration
        try:
            with open(CONFIG_FILE, 'w') as configfile:
                myConfig.write(configfile) 
        except (IOError, OSError):
            print("Error writing to file")
        return True
    return False
    
def main():

    if args.sp == False and args.idp == None:
        parser.print_help()
        exit(0)

    if args.sp:
        if getInputs(SP):
            setupSPDomain()
            print("Service Provider setup complete!")

    if args.idp == 'oci':
        if getInputs(OCI_IDP):
            setupIDPDomain()
            print("Identity Provider setup complete!")
    
    if args.idp != None and args.idp !='oci':
        print("IDP NOT SUPPORTED YET")

    return None


if __name__ == "__main__":
        main()