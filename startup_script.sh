#!/bin/bash
###########################################################################
##       ffff55555                                                       ##
##     ffffffff555555                                                    ##
##   fff      f5    55         Deployment Script Version 0.0.1           ##
##  ff    fffff     555                                                  ##
##  ff    fffff f555555                                                  ##
## fff       f  f5555555             Written By: EIS Consulting          ##
## f        ff  f5555555                                                 ##
## fff   ffff       f555             Date Created: 11/23/2015            ##
## fff    fff5555    555             Last Updated: 12/09/2015            ##
##  ff    fff 55555  55                                                  ##
##   f    fff  555   5       This script will finish setting up a full   ##
##   f    fff       55       Open Cart Web Server with updates           ##
##    ffffffff5555555                                                    ##
##       fffffff55                                                       ##
###########################################################################
###########################################################################
##                              Change Log                               ##
###########################################################################
## Version #     Name       #                    NOTES                   ##
###########################################################################
## 11/23/15#  Thomas Stanley#    Created base functionality              ##
###########################################################################

apt-get update

apt-get -y install build-essential libssl-dev binutils binutils-dev openssl
apt-get -y install libdb-dev libexpat1-dev automake checkinstall unzip elinks sshpass

apt-get -y install apache2 libapache2-mod-perl2
apt-get -y install libcrypt-ssleay-perl libwww-perl libhtml-parser-perl libwww-mechanize-perl
apt-get -y install php5
a2enmod ssl
a2ensite default-ssl
apt-get -y install php5-mcrypt
php5enmod mcrypt
apt-get -y install php5-gd
apt-get -y install php5-curl
apt-get -y install php5-mysql
service apache2 restart

unzip ./opencart-2.0.1.1.zip
echo "Finished inflating zip file."
mv opencart-2.0.1.1/upload /var/www/html/opencart
mv /var/www/html/opencart/config-dist.php /var/www/html/opencart/config.php
mv /var/www/html/opencart/admin/config-dist.php /var/www/html/opencart/admin/config.php
echo "Moved config files."

echo "Wait for the SQL server to come alive!"
i=0
while [ $i == 0 ]
do
sshpass -p${6} ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${5}@$1 "mysql -u opencart -p${6} -Bse 'select 1;'"
status=$?
if [ $status == 0 ]
then
   i=$[$i+1]
else
   echo "Sleeping for 10 seconds while we wait for the MySQL server to come online."
   sleep 10
fi
done
echo "SQL server is now alive."

sqlserver=$(nslookup $1 | awk '/^Address: / { print $2 }')
echo "Grabbed the IP address ($sqlserver) of the SQL Server."

# Try to install OpenCart via command line.
i2=0
php /var/www/html/opencart/install/cli_install.php install --db_hostname $sqlserver --db_username "opencart" --db_password $6 --db_database "opencart" --db_driver mysqli --username admin --password $6 --email "${5}@f5.com" --http_server "http://${2}.westus.cloudapp.azure.com/"  || i2=$[$i2+1]

if [ $i2 == 1 ]
then
   # We failed to install because anothe webserver beat us to it.
   # So we will finish what we have to do, and wait to recieve the config files and have our apache2 restarted.
   sed -e 's|/html|/html/opencart|' -i /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/default-ssl.conf
   echo "Edited the apache files."
   chmod 777 -R /var/www/html/opencart
   echo "chmod opencart directory."
   rm -dfr /var/www/html/opencart/install
   echo "Deleted opencart install directory."
   echo "Finished, waiting for our opencart configuration to be updated by the successful server."
else
   # We succeded because we were the first!
   # Everyone else will fail, so we need to push our config to the others and restart their apache2 server.
   sleep 20
   number=$3
   newnumber=$(( number - 1 ))
   nameprefix=$4
   host=$( hostname )
   for t in $( seq 0 $newnumber); do      
      newname=${nameprefix}${t}
      if [ $newname == $host ]
      then
         echo "This is me!"
      else
	     i=0
		 while [ $i == 0 ]
		 do
		 sshpass -p${6} ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${5}@$newname "cat /var/www/html/opencart/config.php"
		 status=$?
		 if [ $status == 0 ]
		 then
		    echo "Sending our configuraiton files to server $newname."
            sshpass -p${6} scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /var/www/html/opencart/config.php $5@$newname:/var/www/html/opencart/config.php
		    sshpass -p${6} scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /var/www/html/opencart/admin/config.php $5@$newname:/var/www/html/opencart/admin/config.php
		    sshpass -p${6} ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $5@$newname "sudo service apache2 restart"
		    sshpass -p${6} ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $5@$newname "logger 'This Apache Web Server is now ready to host OpenCart...'"
		    i=$[$i+1]
		 else
		    echo "Sleeping for 10 seconds while we wait for ${newname} to come online."
		    sleep 10
		 fi
		 echo "Finished sending our config to $newname."
		 done	     
      fi	  
   done
   sed -e 's|/html|/html/opencart|' -i /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/default-ssl.conf
   echo "Edited the apache files."
   chmod 777 -R /var/www/html/opencart
   echo "chmod opencart directory."
   rm -dfr /var/www/html/opencart/install
   echo "Deleted opencart install directory."
   service apache2 restart
   echo "Restarted Apache."
   echo "This Apache Web Server is now hosting OpenCart..."
fi
