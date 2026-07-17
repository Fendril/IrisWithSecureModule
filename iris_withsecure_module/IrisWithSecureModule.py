#!/usr/bin/env python3

# Import the IrisInterface class
from . import IrisWithSecureConfig as interface_conf
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface
import re

from iris_withsecure_module.ws_handler.ws_handler import WSHandler

# Create our module class
class IrisWithSecureModule(IrisModuleInterface):
    # Set the configuration
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = interface_conf.module_type

    def register_hooks(self, module_id: int):
        """
        Called by IRIS indicating it's time to register hooks.  

        :param module_id: Module ID provided by IRIS.
        """
        # Call the hook registration method. We need to pass the 
        # the module_id to this method, otherwise IRIS won't know 
        # to whom associate the hook. 
        # The hook name needs to be a well known hook name by IRIS. 
        status = self.register_to_hook(module_id, iris_hook_name='on_manual_trigger_case', manual_hook_name='WithSecure: Get Assets/IoCs from BCD')
        if status.is_failure():
            # If we have a failure, log something out 
            self.log.error(status.get_message())
        else:
            # Log that we successfully registered to the hook 
            self.log.info(f"Successfully subscribed to on_manual_trigger_case hook")

    def hooks_handler(self, hook_name: str, hook_ui_name:str, data:dict):
        """
        Called by IRIS each time one of our hook is triggered. 
        """
        # read the current configuration and only log the call if 
        # our parameter is set to true
        self.log.info(f'Received {hook_name}')
        if hook_name == 'on_manual_trigger_case':
            reg = re.compile(r"(?i)(?:ID\s*WithSecure|ID\s*WS|WS\s*ID|WithSecure\s*ID)\s*[:=]\s*([a-z0-9]{8}(?:-[a-z0-9]{4}){3}-[a-z0-9]{12})")
            cap = reg.search(data[0].description)
            if cap:
                status = self._handle_bcd(cap.group(1), data[0].case_id)
                #if status.is_failure():
                #    self.log.error(f'Encountered error processing hook {hook_name}')
                #    return InterfaceStatus.I2Error(data=data, log=list(self.message_queue))
            else:
                self.log.error(f"Received right hook, but can't find any WithSecure BCD ID.")
                return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))
        
        # Return a standardized message to IRIS saying that everything is ok. 
        # logs=list(self.message_queue) is needed, so the users can see the logs 
        # our module generated during its execution.  
        return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))
    
    def _handle_bcd(self, bcd_id: str, case_id: int):
        """
        Handle th BCD data the module just received. The module registered
        to on_manual_trigger_case, so it receives a BCD ID string.
        
        :param bcd_id: WithSecure BCD ID to gather.
        :type bcd_id: str
        """
        in_status = InterfaceStatus.IIStatus(code=InterfaceStatus.I2CodeNoError)

        ws_handler = WSHandler(logger=self.log, case_id=case_id, mod_config=self._dict_conf)

        status = ws_handler.load_withsecure_instance()
        in_status = InterfaceStatus.merge_status(in_status, status)

        status = ws_handler.get_detections(bcd_id)
        in_status = InterfaceStatus.merge_status(in_status, status)

        return in_status()