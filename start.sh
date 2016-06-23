#!/bin/bash
###########################################################################
##       ffff55555                                                       ##
##     ffffffff555555                                                    ##
##   fff      f5    55         Deployment Script Version 0.0.1           ##
##  ff    fffff     555                                                  ##
##  ff    fffff f555555                                                  ##
## fff       f  f5555555             Written By: EIS Consulting          ##
## f        ff  f5555555                                                 ##
## fff   ffff       f555             Date Created: 12/02/2015            ##
## fff    fff5555    555             Last Updated: 01/21/2016            ##
##  ff    fff 55555  55                                                  ##
##   f    fff  555   5       This script will licens and pre-configure a ##
##   f    fff       55       BIG-IP for use in Azure                     ##
##    ffffffff5555555                                                    ##
##       fffffff55                                                       ##
###########################################################################
###########################################################################
##                              Change Log                               ##
###########################################################################
## Version #     Name       #                    NOTES                   ##
###########################################################################
## 06/22/16#  Gregory Coward#    Created base functionality              ##
###########################################################################

### Parameter Legend  ###
## devicepwd=0 #login password for the BIG-IP
## devicelic=1 #BYOL License key


## Build the arrays based on the semicolon delimited command line argument passed from json template.
IFS=';' read -ra devicearr <<< "$1"    

## Construct the blackbox.conf file using the arrays.
tempfile1='{
 "bigip":{
      "application_name":"My Application",
      "ntp_servers":"1.pool.ntp.org 2.pool.ntp.org",              
      "ssh_key_inject":"false",
      "change_passwords":"false",
      "license":{
           "basekey":"' 

$tempfile2='"
      },
      "modules":{
           "auto_provision":"true",
           "ltm":"nominal",
           "apm":"nominal"
      },
      "network":{
			"provision": "false"
		}
       }
}'

jsonfile= $tempfile1 + ${devicearr[0]} + $tempfile2

echo $jsonfile > /config/blackbox.conf

## Move the files and run them.
mv ./autoconfig.sh /config/autoconfig.sh
chmod +w /config/startup
echo "/config/autoconfig.sh" >> /config/startup
chmod u+x /config/autoconfig.sh
bash /config/autoconfig.sh