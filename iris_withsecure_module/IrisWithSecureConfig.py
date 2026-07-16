# Import the module types list,  so we can indicate the type of our module 
from iris_interface.IrisModuleInterface import IrisModuleTypes 

# Human name displayed in the GUI Manage > Modules. This can be anything, 
# but try to put something meaningful, so users recognize your module. 
module_name = "IrisWithSecureModule"

# Description displayed when editing the module configuration in the UI. 
# This can be anything, 
module_description = "Provides a WithSecure module that gather information from an EDR Event with the WithSecure ID."

# Set the interface version used. This needs to be the version of 
# the IrisModuleInterface package. This version is check by the server to
# to ensure our module can run on this specific server 
interface_version = 1.2

# The version of the module itself, it can be anything 
module_version = 1.0

# The type of the module, here processor 
module_type = IrisModuleTypes.module_processor

# Our module is a processor type, so it doesn't offer any pipeline 
pipeline_support = False

# Provide no pipeline information as our module don't implement any 
pipeline_info = {}

# The configuration of the module that will be displayed and configurable 
# by administrators on the UI. This describes every parameter that can 
# be set. 
module_configuration = [
    {
        "param_name": "withsecure_api_clientid",
        "param_human_name": "WithSecure API Key ClientID",
        "param_description": "API key ClientID to interact with WithSecure. Read-only key is recommanded.",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {     
        "param_name": "withsecure_api_secret", 
        "param_human_name": "WithSecure API Key Secret",    
        "param_description": "API key Secret to interact with WithSecure. Read-only key is recommended.", 
        "default": None, 
        "mandatory": True, 
        "type": "sensitive_string"
    },
    {     
        "param_name": "iris_fqdn", 
        "param_human_name": "FQDN name of DFIR-IRIS",    
        "param_description": "FQDN name of the DFIR-IRIS instance, used for web access or URL. (ex: myiris.domain.loc)", 
        "default": None, 
        "mandatory": True, 
        "type": "string"
    },
    {     
        "param_name": "iris_api_key", 
        "param_human_name": "DFIR-IRIS API Key",    
        "param_description": "API key to interact with DFIR-IRIS itself. (Key need write IoCs and Assets rights.)", 
        "default": None, 
        "mandatory": True, 
        "type": "sensitive_string"
    },
]