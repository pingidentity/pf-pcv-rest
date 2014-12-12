#pf-pcv-rest

### Overview

PingFederate password credential validator to check username/password against a generic REST service.


### System Requirements / Dependencies

Requires:
 - PingFederate 7.2.x or higher
 - Simple JSON
 - Apache Commons logging

 
### Installation
 
1. Compile the plugin in (refer to the [PingFederate server SDK documentation] for details on compiling PingFederate plug-ins)
2. Copy the resulting .jar file to the <pf_home>/server/default/deploy folder (on all nodes and admin instances).
3. Restart PingFederate
 
[PingFederate server SDK documentation]: http://documentation.pingidentity.com/display/PF/SDK+Developer%27s+Guide


### Configuration

Once the plug-in has been deployed and the PingFederate instance restarted, launch the PingFederate admin console:

1. Create a new password credential validator instance under: Authentication > Password Credential Validators
2. Name the instance and select "REST Service Password Credential Validator" as the type
3. Refer to the inline documentation to configure your REST endpoint details


### Disclaimer

This software is open sourced by Ping Identity but not supported commercially as such. Any questions/issues should go to the mailing list, the Github issues tracker or the author pmeyer@pingidentity.com directly See also the DISCLAIMER file in this directory.