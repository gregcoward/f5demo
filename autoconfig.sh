#!/bin/bash
###########################################################################
##       ffff55555                                                       ##
##     fffff f555555                                                     ##
##   fff      f5    5          ISC LAB  Deployment Script Version 1.0.1  ##
##  ff    fffff     555                                                  ##
##  ff    fffff f555555                                                  ##
## fff       f     55555             Written By: F5 Networks             ##
## f        ff     55555                                                 ##
## fff   ffff      ..:55             Date Created: 10/20/2015            ##
## fff    fff5555 ..::,5                                                 ##
##  ff    fff 555555,;;                                                  ##
##   f    fff  55555,;       This script is a modified version of the    ##
##   f    fff    55,55         OpenStack auto-configuration script       ##
##    ffffffff5555555       Written by John Gruber and George Watkins    ##
##       fffffff55                                                       ##
###########################################################################
###########################################################################

shopt -s extglob
export PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin/"

# Logging settings
LOGGER_TAG="blackbox-init"
LOGGER_CMD="logger -t $LOGGER_TAG"

# Wait for process settings
STATUS_CHECK_RETRIES=60
STATUS_CHECK_INTERVAL=10

# Blackbox user-data settings
OS_USER_DATA_RETRIES=20
OS_USER_DATA_RETRY_INTERVAL=10
OS_USER_DATA_RETRY_MAX_TIME=300
OS_USER_DATA_PATH="/config/blackbox.conf"
OS_USER_DATA_TEMP_PATH="/config/formatted_blackbox.conf"
OS_USER_DATA_TMP_FILE="/config/iapp_temp"
OS_USER_DATA_STATUS_PATH="/config/blackbox.status"

# BIG-IP password settings
OS_CHANGE_PASSWORDS=false

# BIG-IP licensing settings
BIGIP_LICENSE_FILE="/config/bigip.license"
BIGIP_LICENSE_RETRIES=5
BIGIP_LICENSE_RETRY_INTERVAL=5

# BIG-IP module provisioning
BIGIP_PROVISIONING_ENABLED=true
BIGIP_AUTO_PROVISIONING_ENABLED=false

# TMM interfaces network settings
OS_DHCP_ENABLED=true
OS_DHCP_LEASE_FILE="/tmp/blackbox-dhcp.leases"
OS_DHCP_REQ_TIMEOUT=30
OS_VLAN_PREFIX="blackbox-network-"
OS_VLAN_DESCRIPTION="auto-added by blackbox-init"
OS_SELFIP_PREFIX="blackbox-dhcp-"
OS_SELFIP_ALLOW_SERVICE="none"
OS_SELFIP_DESCRIPTION="auto-added by blackbox-init"
OS_PROVISION_FILE="/tmp/blackbox-provision"
# Regular expressions
LEVEL_REGEX='^(dedicated|minimum|nominal|none)$'
PW_REGEX='^\$[0-9][A-Za-z]?\$'
TMM_IF_REGEX='^1\.[0-9]$'
IP_REGEX='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
SELFIP_ALLOW_SERVICE_REGEX='^(all|default|none)$'

# insert tag and log
function log() {
  echo "$1" | eval "$LOGGER_CMD"
}

function set_status() {
  echo "$1" > $OS_USER_DATA_STATUS_PATH
}


function upcase() {
  echo "$1" | tr '[a-z]' '[A-Z]'
}

function get_json_value() {
  echo -n $(perl -MJSON -ne "\$value = decode_json(\$_)->$1; \
    \$value =~ s/([^a-zA-Z0-9])/\$1/g; print \$value" $2)
}



function get_user_data_value() {
  echo -n $(get_json_value $1 $OS_USER_DATA_TEMP_PATH)
}

function get_user_data_system_cmds() {
  echo -n $(perl -MJSON -ne "print join(';;', \
  @{decode_json(\$_)->{bigip}{system_cmds}})" $OS_USER_DATA_TEMP_PATH)
}

function generate_sha512_passwd_hash() {
  salt=$(openssl rand -base64 8)
  echo -n $(perl -e "print crypt(q[$1], \"\\\$6\\\$$salt\\\$\")")
}

function get_dhcp_server_address() {
  echo -n $(awk '/dhcp-server-identifier/ { print $3 }' \
    /var/lib/dhclient/dhclient.leases | tail -1 | tr -d ';')
}



# check state
function wait_status_active() {
  failed=0
  while true; do
   state_started=$(cat /var/prompt/ps1)

    if [[ $state_started == Active ]]; then
      log "detected system Active"
      return 0
    fi

    failed=$(($failed + 1))

    if [[ $failed -ge $STATUS_CHECK_RETRIES ]]; then
      log "System was not Active after $failed checks, quitting..."
      set_status "Failure: System was not Active after $failed checks"
      return 1
    fi

    log "System was not Active (check $failed/$STATUS_CHECK_RETRIES), retrying in $STATUS_CHECK_INTERVAL seconds..."
    sleep $STATUS_CHECK_INTERVAL
  done
}

# check if MCP is running
function wait_mcp_running() {
  failed=0

  while true; do
    mcp_started=$(bigstart_wb mcpd start)

    if [[ $mcp_started == released ]]; then
      # this will log an error when mcpd is not up
      tmsh -a show sys mcp-state field-fmt | grep -q running 

      if [[ $? == 0 ]]; then
        log "Successfully connected to mcpd..."
        return 0
      fi
    fi

    failed=$(($failed + 1))

    if [[ $failed -ge $STATUS_CHECK_RETRIES ]]; then
      log "Failed to connect to mcpd after $failed attempts, quitting..."
      set_status "Failure: Failed to connect to mcpd after $failed attempts"      
      return 1
    fi

    log "Could not connect to mcpd (attempt $failed/$STATUS_CHECK_RETRIES), retrying in $STATUS_CHECK_INTERVAL seconds..."
    sleep $STATUS_CHECK_INTERVAL
  done
}

# wait for tmm to start
function wait_tmm_started() {
  failed=0

  while true; do
    tmm_started=$(bigstart_wb tmm start)

    if [[ $tmm_started == released ]]; then
      log "detected tmm started"
      return 0
    fi

    failed=$(($failed + 1))

    if [[ $failed -ge $STATUS_CHECK_RETRIES ]]; then
      log "tmm was not started after $failed checks, quitting..."
      set_status "Failure: tmm was not started after $failed checks"  
      return 1
    fi

    log "tmm not started (check $failed/$STATUS_CHECK_RETRIES), retrying in $STATUS_CHECK_INTERVAL seconds..."
    sleep $STATUS_CHECK_INTERVAL
  done
}


# extract license from JSON data and license unit
function license_bigip() {
  host=$(get_user_data_value {bigip}{license}{host})
  basekey="UXQHV-ACQQX-TQOSQ-RROUL-YBOEFUN"  
  basekeyfile=$(get_user_data_value {bigip}{license}{basekeyfile})  
    if [[ -n $basekeyfile ]]; then
   	    basekey=`cat $basekeyfile`
    fi
  addkey=$(get_user_data_value {bigip}{license}{addkey})
  sed -ised -e 's/sleep\ 5/sleep\ 10/' /etc/init.d/mysql
  rm -f /etc/init.d/mysqlsed
  if [[ ! -s $BIGIP_LICENSE_FILE ]]; then
    if [[ -n $basekey ]]; then
      failed=0

      # if a host or add-on key is provided, append to license client command
      [[ -n $host ]] && host_cmd="--host $host"
      [[ -n $addkey ]] && addkey_cmd="--addkey $addkey"

      while true; do
        log "Licensing BIG-IP using license key $basekey..."
        SOAPLicenseClient $host_cmd --basekey $basekey $addkey_cmd 2>&1 | eval $LOGGER_CMD

        if [[ $? == 0 && -f $BIGIP_LICENSE_FILE ]]; then
          log "Successfully licensed BIG-IP using user-data from instance metadata..."
          return 0
        else
          failed=$(($failed + 1))

          if [[ $failed -ge $BIGIP_LICENSE_RETRIES ]]; then
            log "Failed to license BIG-IP after $failed attempts, quitting..."
            set_status "Failure: Failed to license BIG-IP after $failed attempts" 
            exit
            return 1
          fi

          log "Could not license BIG-IP (attempt #$failed/$BIGIP_LICENSE_RETRIES), retrying in $BIGIP_LICENSE_RETRY_INTERVAL seconds..."
          sleep $BIGIP_LICENSE_RETRY_INTERVAL
        fi
      done
    else
      log "No BIG-IP license key found..."
      set_status "Failure: No BIG-IP license key found" 
      exit
      return 1      
    fi
  else
    log "BIG-IP already licensed, skipping license activation..."
  fi
}

# return list of modules supported by current platform
function get_supported_modules() {
  echo -n $(tmsh list sys provision one-line | awk '/^sys/ { print $3 }')
}


# retrieve enabled modules from BIG-IP license file
function get_licensed_modules() {
  if [[ -s $BIGIP_LICENSE_FILE ]]; then
    provisionable_modules=$(get_supported_modules)
    enabled_modules=$(awk '/^mod.*enabled/ { print $1 }' /config/bigip.license |
      sed 's/mod_//' | tr '\n' ' ')

    for module in $enabled_modules; do
      case $module in
        wo@(c|m)) module="wom" ;;
        wa?(m)) module="wam" ;;
        af@(m|w)) module="afm" ;;
        am) module="apm" ;;
      esac
      
      if [[ "$provisionable_modules" == *"$module"* ]]; then
        licensed_modules="$licensed_modules $module"
        log "Found license for $(upcase $module) module..."
      fi
    done
    
    echo "$licensed_modules"
  else 
    log "Could not locate valid BIG-IP license file, no licensed modules found..."
  fi
}

# provision BIG-IP software modules 
function provision_modules() {
  [[ -f $OS_PROVISION_FILE ]] && rm -f $OS_PROVISION_FILE
  # get list of licensed modules
  licensed_modules=$(get_licensed_modules)
  provisionable_modules=$(get_supported_modules)
  
  # if auto-provisioning enabled, obtained enabled modules list from license \
  # file
  auto_provision=$(get_user_data_value {bigip}{modules}{auto_provision})
  log "auto_provision userdata set to $auto_provision"
  [[ $BIGIP_AUTO_PROVISIONING_ENABLED == false ]] && auto_provision=false 
  log "auto_provision after check, set to $auto_provision"
    
  for module in $licensed_modules; do 
    level=$(get_user_data_value {bigip}{modules}{$module})
        
    if [[ "$provisionable_modules" == *"$module"* ]]; then
      if [[ ! $level =~ $LEVEL_REGEX ]]; then 
        if [[ $auto_provision == true ]]; then
          level=nominal
        else
          level=none
        fi
      fi
      
       echo -e "sys provision $module { level $level }" >> $OS_PROVISION_FILE
       #also write to base so when we come back up we don't then depro the modules
       echo -e "sys provision $module { level $level }" >> /config/bigip_base.conf
      

    fi     
  done
	#provision all at once
	tmsh load sys config merge file $OS_PROVISION_FILE &> /dev/null

	if [[ $? == 0 ]]; then
	log "Successfully provisioned `cat $OS_PROVISION_FILE`"
   	else
	log "Failed to provision , examine /var/log/ltm for more information..."
	set_status "Failure: Failed to provision" 
	fi  
 }

function change_passwords() {
  root_password=$(get_user_data_value {bigip}{root_password})
  admin_password=$(get_user_data_value {bigip}{admin_password})
  
  change_passwords=$OS_CHANGE_PASSWORDS
  [[ $change_passwords == true && \
    $(get_user_data_value {bigip}{change_passwords}) == false ]] && \
    change_passwords=false

  if [[ $change_passwords == true ]]; then
    for creds in root:$root_password admin:$admin_password; do
      user=$(cut -d ':' -f1 <<< $creds)
      password=$(cut -d ':' -f2 <<< $creds)

      if [[ -n $password ]]; then
        if [[ $password =~ $PW_REGEX ]]; then
          password_hash=$password
          log "Found hash for salted password, successfully changed $user password..."
        else
          password_hash=$(generate_sha512_passwd_hash "$password")
          log "Found plain text password and (against my better judgment) successfully changed $user password..."
        fi

        sed -e "/auth user $user/,/}/ s|\(encrypted-password \).*\$|\1\"$password_hash\"|" \
	        -i /config/bigip_user.conf
      else
        log "No $user password found in user-data, skipping..."
      fi
    done

    tmsh load sys config user-only 2>&1 | eval $LOGGER_CMD
  else
    log "Password changed have been disabled, skipping..."
  fi

}

function set_tmm_if_selfip() {
  tmm_if=$1
  address=$2
  netmask=$3
  router=$4
  
  unset dhcp_enabled selfip_prefix selfip_name selfip_description selfip_allow_service vlan_name
  
  if [[ $address =~ $IP_REGEX && $netmask =~ $IP_REGEX ]]; then
    dhcp_enabled=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{dhcp})
    vlan_name=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{vlan_name})
    selfip_prefix=$(get_user_data_value {bigip}{network}{selfip_prefix})
    selfip_name=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{selfip_name})
    selfip_description=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{selfip_description})
    selfip_allow_service=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{selfip_allow_service})
    
    [[ -z $selfip_prefix ]] && selfip_prefix=$OS_SELFIP_PREFIX
    [[ -z $selfip_name ]] && selfip_name="${selfip_prefix}${tmm_if}"
    [[ -z $selfip_description ]] && selfip_description=$OS_SELFIP_DESCRIPTION
    [[ -z $selfip_allow_service ]] && selfip_allow_service=$OS_SELFIP_ALLOW_SERVICE
    
    if [[ $dhcp_enabled == false ]]; then
      log "Configuring self IP $selfip_name on VLAN $vlan_name with static address $address/$netmask..."
    else
      log "Configuring self IP $selfip_name on VLAN $vlan_name with DHCP address $address/$netmask..."
    fi

    selfip_cmd="tmsh create net self $selfip_name address $address/$netmask allow-service $selfip_allow_service vlan $vlan_name description \"$selfip_description\""
    log "  $selfip_cmd"
    eval "$selfip_cmd 2>&1 | $LOGGER_CMD"
  fi
  
    #setup default route
    default_route=$(get_user_data_value {bigip}{network}{default_route})
    if [[ -z $default_route ]]; then
   	    default_route=$router  	    
	    if [[ -n $default_route ]]; then	    
		tmsh create net route default_ipv4 { gw $default_route network default }
		log "Setting default route to $default_route" 
	    fi
    fi
}

function set_tmm_if_vlan() {
  tmm_if=$1

  unset vlan_prefix vlan_name vlan_description vlan_tag tagged vlan_tag_cmd tagged_cmd

  if [[ $tmm_if =~ $TMM_IF_REGEX ]]; then
    vlan_prefix=$(get_user_data_value {bigip}{network}{vlan_prefix})
    vlan_name=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{vlan_name})
    vlan_description=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{vlan_description})
    vlan_tag=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{vlan_tag})
    tagged=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{tagged})


    [[ -z $vlan_prefix ]] && vlan_prefix=$OS_VLAN_PREFIX
    [[ -z $vlan_name ]] && vlan_name="${vlan_prefix}${tmm_if}"
    [[ -z $vlan_description ]] && vlan_description=$OS_VLAN_DESCRIPTION

    if [[ $tagged == true && tagged_cmd="{ tagged } " ]]; then
      if [[ $vlan_tag -ge 1 && $vlan_tag -le 4096 ]]; then
        vlan_tag_cmd=" tag $vlan_tag "
        log "Configuring VLAN $vlan_name with tag $vlan_tag on interface $tmm_if..."
      fi
    else
      log "Configuring VLAN $vlan_name on interface $tmm_if..."
    fi

    vlan_cmd="tmsh create net vlan $vlan_name interfaces add { $tmm_if $tagged_cmd}$vlan_tag_cmd description \"$vlan_description\""

    log "  $vlan_cmd"
    eval "$vlan_cmd 2>&1 | $LOGGER_CMD"
  fi
}

function dhcp_tmm_if() {
  [[ -f $OS_DHCP_LEASE_FILE ]] && rm -f $OS_DHCP_LEASE_FILE

  log "Issuing DHCP request on interface 1.${1:3}..."
  dhclient_cmd="dhclient -lf $OS_DHCP_LEASE_FILE -cf /dev/null -1 -T \
    $OS_DHCP_REQ_TIMEOUT -sf /bin/echo -R \
    subnet-mask,broadcast-address,routers $1"
  eval "$dhclient_cmd 2>&1 | sed -e '/^$/d' -e 's/^/  /' | $LOGGER_CMD"
  pkill dhclient

  if [[ -f $OS_DHCP_LEASE_FILE ]]; then 
    dhcp_offer=`awk 'BEGIN {
      FS="\n"
      RS="}"
    }
    /lease/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /interface/) {
          gsub(/[";]/,"",$i)
          sub(/eth/, "1.", $i)
          split($i,INT," ")
          interface=INT[2]
        }
        if ($i ~ /fixed/) {
          sub(/;/,"",$i)
          split($i,ADDRESS," ")
          address=ADDRESS[2]
        }
        if ($i ~ /mask/) {
          sub(/;/,"",$i)
          split($i,NETMASK, " ")
          netmask=NETMASK[3]
        }
        if ($i ~ /routers/) {
          sub(/;/,"",$i)
          split($i,ROUTE, " ")
          router=ROUTE[3]
        }        
      }

      print interface " " address " " netmask " " router
          
    }' $OS_DHCP_LEASE_FILE`


 
    rm -f $OS_DHCP_LEASE_FILE
    
    

    echo $dhcp_offer
  fi
}

function configure_tmm_ifs() {
  tmm_ifs=$(ip link sh | egrep '^[0-9]+: eth[1-9]' | cut -d ' ' -f2 | 
    tr -d  ':')
    
  dhcp_enabled_global=$OS_DHCP_ENABLED
  [[ $dhcp_enabled_global == true && \
    $(get_user_data_value {bigip}{network}{dhcp}) == false ]] && \
    dhcp_enabled_global=false
    
    
    
  if [[ $dhcp_enabled_global == true ]]; then
    # stop DHCP for management interface because only one dhclient process can run at a time
    log "Stopping DHCP client for management interface..."
    service dhclient stop  &> /dev/null
    sleep 1
  fi

  [[ $dhcp_enabled_global == false ]] &&
    log "DHCP disabled globally, will not auto-configure any interfaces..."

  for interface in $tmm_ifs; do
    tmm_if="1.${interface:3}"
    dhcp_enabled=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{dhcp})

    # setup VLAN
    tmsh list net vlan one-line | grep -q "interfaces { .*$1\.${interface:3}.* }"

    if [[ $? != 0 ]]; then
      set_tmm_if_vlan $tmm_if
    else  
      log "VLAN already configured on interface $tmm_if, skipping..."
    fi
      
    # setup self-IP
    vlan_name=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{vlan_name})
    [[ -z $vlan_name ]] && vlan_name="${vlan_prefix}${tmm_if}"
    tmsh list net self one-line | grep -q "vlan $vlan_name"
    
    if [[ $? != 0 ]]; then
      if [[ $dhcp_enabled_global == false || $dhcp_enabled == false ]]; then
        # DHCP is disabled, look for static address and configure it
        address=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{address})
        netmask=$(get_user_data_value {bigip}{network}{interfaces}{$tmm_if}{netmask})

        if [[ -n $address && -n $netmask ]]; then
          set_tmm_if_selfip $tmm_if $address $netmask
        else
          log "DHCP is disabled and no static address could be located for $tmm_if, skipping..."
        fi
      else
        set_tmm_if_selfip $(dhcp_tmm_if $interface)  
        sleep 2
      fi
    else
      log "Self IP already configured for interface $tmm_if, skipping..."
    fi
  done
  

  if [[ $dhcp_enabled_global == true ]]; then
    # restart DHCP for management interface
    log "Restarting DHCP client for management interface..."
    service dhclient restart &> /dev/null
    #tmsh modify sys db dhclient.mgmt { value disable }
  fi
  
    default_route=$(get_user_data_value {bigip}{network}{default_route})

    if [[ -n $default_route ]]; then
	tmsh create net route default_ipv4 { gw $default_route network default }
	log "Setting default route to $default_route" 
    fi
 
  
  log "Saving after configuring interfaces"
  tmsh save sys config | eval $LOGGER_CMD
}

function execute_system_cmd() {
  system_cmds=$(get_user_data_system_cmds)
  
  IFS=';;'
  for system_cmd in $system_cmds; do
    if [[ -n $system_cmd ]]; then
      log "Executing system command: $system_cmd..."
      eval "$system_cmd 2>&1 | sed -e '/^$/d' -e 's/^/  /' | $LOGGER_CMD"
    fi
  done
  unset IFS
}

function webserv() {
  tmsh create ltm pool WebPool members add { 10.0.0.8:80 } monitor http
  tmsh create ltm virtual OnPremWeb destination 10.0.0.10:6444 profiles add { clientssl http } pool WebPool snat automap persist replace-all-with { cookie } fallback-persistence source_addr
}

function main() {
  start=$(date +%s)
  log "Starting Blackbox auto-configuration..."
  set_status "In Progress: Starting Configuration"
    
    #ensure json format - remove new lines
	  cat $OS_USER_DATA_PATH | sed 's/\t/ /g' | sed ':a;N;$!ba;s/\n/ /g'  > $OS_USER_DATA_TEMP_PATH
    
    # ensure that mcpd is started and alive before doing anything
    wait_mcp_running
    set_status "In Progress: Connected to system"

    if [[ $? == 0 ]]; then
      sleep 10
      tmsh save sys config | eval $LOGGER_CMD
      
      
      	network_provision=$(get_user_data_value {bigip}{network}{provision})
      	if [[ $network_provision != "false" ]]; then
          configure_tmm_ifs
          wait_tmm_started
        fi
        
        dns_servers=$(get_user_data_value {bigip}{name_servers})
	if [[ -n $dns_servers ]]; then
	  tmsh modify sys dns name-servers replace-all-with { $dns_servers }
 	  log "Setting dns servers to $dns_servers" 
 	fi
 	
 	#check for resolv.conf
 	resolvconf=`cat /etc/resolv.conf`
	if [[ $resolvconf == "search localdomain" ]]; then
          nameserver=`tmsh list sys dns name-servers  | awk 'BEGIN {RS=""}{gsub(/\n/,"",$0); print $6}'`
          echo -e "search localhost\nnameserver      $nameserver\noptions ndots:0" > /etc/resolv.conf
 	fi 	
 	
 	
 	
  
 	ntp_servers=$(get_user_data_value {bigip}{ntp_servers})
	if [[ -n $ntp_servers ]]; then
	  tmsh modify sys ntp servers replace-all-with { $ntp_servers }
  	  log "Setting ntp servers to $ntp_servers" 
          sleep 10 
        fi
        
        tmsh save sys config | eval $LOGGER_CMD
        set_status "In Progress: Licensing"     	
        license_bigip
        set_status "In Progress: Licensing - OK" 
        set_status "In Progress: Provisioning" 
        provision_modules
        sleep 10
        wait_status_active
        status=$?
        selfip_check=`tmsh list net self one-line`
        if [[ $status == 1 || -z $selfip_check ]]; then
        	log "We need to reboot to complete deployment"
        	set_status "In Progress: Rebooting"
        	reboot
        	exit
        fi  
        set_status "In Progress: Provisioning - OK" 
        execute_system_cmd

      wait_mcp_running
      # wait for stuff to restart
      sleep 10
      wait_mcp_running
      wait_tmm_started
      log "Changing db settings..."
      tmsh modify sys global-settings gui-setup disabled | eval $LOGGER_CMD

      sleep 10   
      webserv
      sleep 10   
      tmsh save sys config | eval $LOGGER_CMD 
      fi

  finish=$(date +%s)
  log "Completed BlackBox auto-configuration in $(($finish-$start)) seconds..."
  set_status "OK"
  rm $0
}

# immediately background script to prevent blocking of MCP from starting
main &
