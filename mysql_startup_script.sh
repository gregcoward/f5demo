#!/bin/bash
###########################################################################
##       ffff55555                                                       ##
##     ffffffff555555                                                    ##
##   fff      ff    55         Deployment Script Version 0.0.1           ##
##  ff    fffff     555                                                  ##
##  ff    fffff  555555                                                  ##
## fff       f  f5555555             Written By: EIS Consulting          ##
## f        ff  f5555555                                                 ##
## fff   ffff       f555             Date Created: 11/23/2015            ##
## fff    fff5555    555             Last Updated: 11/23/2015            ##
##  ff    fff  5555  55                                                  ##
##   f    fff  555   5       This script will finish setting up a full   ##
##   f    fff       55       Open Cart MySQL Server with updates         ##
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
apt-get -y install libdb-dev libexpat1-dev automake checkinstall unzip elinks

echo mysql-server mysql-server/root_password password $1 | debconf-set-selections  
echo mysql-server mysql-server/root_password_again password $1 | debconf-set-selections 

apt-get -y install mysql-server
apt-get -y install libmysqld-dev libdb-dev

ipaddr=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
sed 's%127.0.0.1%'$ipaddr'%' -i /etc/mysql/my.cnf 
service mysql restart
mysql -u root -p${1} -Bse "CREATE DATABASE opencart;CREATE USER 'opencart'@'%' IDENTIFIED BY '"$1"';GRANT ALL ON opencart.* TO 'opencart'@'%';flush privileges;"
echo "This MySQL Server is now ready to host OpenCart!"
