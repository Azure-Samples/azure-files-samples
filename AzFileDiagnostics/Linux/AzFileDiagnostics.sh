#! /bin/bash

#global variables
PROG="${0##*/}"
UNCPATH=''
ACCOUNT=''
SHARE=''
ENVIRONMENT='AzureCloud'
SAFQDN=''
IPREGION=''
VALIDATESRVCFG=1
PROTOCOLSETTINGS=''

#Default mount parameters
sec_name="ntlmssp"
smb_ver="3.1.1"

## print the log in custom format <to do: add color support>
print_log()
{
  RED='\033[0;31m'
  YELLOW='\033[0;33m'
  DEFAULT='\033[0m'

  case  "$2" in
    info)
      printf "$(date --utc +%FT%T.%3NZ) ${1}\n" | tee -a $LOGDIR/output.txt
      ;;
    warning)
      printf "${YELLOW}$(date --utc +%FT%T.%3NZ) Warning: ${1}${DEFAULT}\n" | tee -a $LOGDIR/output.txt
      ;;
    error)
      printf "${RED}$(date --utc +%FT%T.%3NZ) Error: ${1}${DEFAULT}\n" | tee -a $LOGDIR/output.txt
      ;;
    *)
      printf "\n$(date --utc +%FT%T.%3NZ) Checking: ${1}\n" | tee -a $LOGDIR/output.txt
      ;;
  esac

}


## ======================================Parse the arguments if it is non-empty=====================================================

## script usage function
usage()
{
	echo "options below are optional"
	echo '-u | --uncpath <value> Specify Azure File share UNC path like //storageaccount.file.core.windows.net/sharename. if this option is provided, below options are ignored'
	echo '-a | --account <value> Specify Storage Account Name'
	echo '-s | --share <value >Specify the file share name'
	echo '-e | --azureenvironment <value> Specify the Azure environment. Valid values are: AzureCloud, AzureChinaCloud, AzureGermanCloud, AzureUSGovernment. The default is AzureCloud'
}


get_server_protocol_settings()
{
	# If you've never changed any SMB security settings, the values for the SMB security
	# settings returned by Azure Files will be null. Null returned values should be interpreted
	# as "default settings are in effect". To make this more user-friendly, the following
	# az cli commands replace null values with the human-readable default values.

	# Values to be replaced
	replaceSmbProtocolVersion="\"smbProtocolVersions\": null"
	replaceSmbChannelEncryption="\"smbChannelEncryption\": null"
	replaceSmbAuthenticationMethods="\"smbAuthenticationMethods\": null"
	replaceSmbKerberosTicketEncryption="\"smbKerberosTicketEncryption\": null"

	# Replacement values for null parameters. If you copy this into your own
	# scripts, you will need to ensure that you keep these variables up-to-date with any new
	# options we may add to these parameters in the future.
	defaultSmbProtocolVersion="\"smbProtocolVersions\": \"SMB2.1;SMB3.0;SMB3.1.1\""
	defaultSmbChannelEncryption="\"smbChannelEncryption\": \"AES-128-CCM;AES-128-GCM;AES-256-GCM\""
	defaultSmbAuthenticationMethods="\"smbAuthenticationMethods\": \"NTLMv2;Kerberos\""
	defaultSmbKerberosTicketEncryption="\"smbKerberosTicketEncryption\": \"RC4-HMAC;AES-256\""

	# Build JMESPath query string
	query="{"
	query="${query}smbProtocolVersions: protocolSettings.smb.versions,"
	query="${query}smbChannelEncryption: protocolSettings.smb.channelEncryption,"
	query="${query}smbAuthenticationMethods: protocolSettings.smb.authenticationMethods,"
	query="${query}smbKerberosTicketEncryption: protocolSettings.smb.kerberosTicketEncryption"
	query="${query}}"

	# Get protocol settings from the Azure Files FileService object
	PROTOCOLSETTINGS=$(az storage account file-service-properties show \
		--account-name $ACCOUNT \
		--query "${query}")
	retVal=$?
	if [ $retVal -ne 0 ]; then
		print_log "Get file service properties operaion failed, Please make sure storage account name is correct" "error"
		exit 1
	fi

	# Replace returned values if null with default values
	PROTOCOLSETTINGS="${PROTOCOLSETTINGS/$replaceSmbProtocolVersion/$defaultSmbProtocolVersion}"
	PROTOCOLSETTINGS="${PROTOCOLSETTINGS/$replaceSmbChannelEncryption/$defaultSmbChannelEncryption}"
	PROTOCOLSETTINGS="${PROTOCOLSETTINGS/$replaceSmbAuthenticationMethods/$defaultSmbAuthenticationMethods}"
	PROTOCOLSETTINGS="${PROTOCOLSETTINGS/$replaceSmbKerberosTicketEncryption/$defaultSmbKerberosTicketEncryption}"
}


validate_smb_version()
{
	supported_ver=$(echo $PROTOCOLSETTINGS  | sed 's/,/\n/g' | grep "smbProtocolVersions" | awk -F\" '{print $(NF-1)}' | sed 's/;/ /g')
	print_log "Choose one of the following SMB versions supported by linux kernel, Default version is recommended " "info"

	if [ "$SMB311" -eq 0 ]; then
		options=('Default' 'SMB3.1.1' 'SMB3.0' 'SMB2.1')
	elif [ "$SMB3" -eq 0 ]; then
		options=('Default' 'SMB3.0' 'SMB2.1')
	else
		options=('Default' 'SMB2.1')
	fi

	select opt in "${options[@]}"
	do
		case $opt in
			"SMB2.1")
				requested_ver="SMB2.1"
				#Check azure portal configurations for secure transfer enable setting
				az storage account show -n $ACCOUNT | grep "enableHttpsTrafficOnly" | grep -q "true"
				retVal=$?
				if [ $retVal -eq 0 ]; then
					print_log "Secure transfer is enabled on server, Please disable to from azure portal to mount SMB2 shares" "error"
					print_log "For more details visit:  https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer" "error"
					exit 1
				fi
				print_log "Make sure your storage account and VM are presnet in same region" "warning"
				break
				;;
			"SMB3.0")
				requested_ver="SMB3.0"
				break
				;;
			"SMB3.1.1")
				requested_ver="SMB3.1.1"
				break
				;;
			"Default")
				requested_ver=${options[1]}
				break
				;;
			*) echo invalid option;;
		esac
	done

	smb_ver=$(echo $requested_ver | cut -c 4-)

	if [[ " $supported_ver " = *" $requested_ver "* ]]; then
		print_log "Requested version $requested_ver is supported by server" "info"
	else
		print_log "Requested version $requested_ver is not present in azure server supported versions:$supported_ver" "error"
		print_log "Enable $requested_ver in server configurations https://docs.microsoft.com/en-us/azure/storage/files/files-smb-protocol?tabs=azure-portal#smb-security-settings" "error"
		exit 1
	fi
}

validate_auth_mechanism()
{
	print_log "Select the Authentication mechanisms" "info"
	options=('Default' 'NTLMv2' 'Kerberos' )

	select opt in "${options[@]}"
	do
		case $opt in
			"NTLMv2")
				requested_sec="NTLMv2"
				sec_name="ntlmssp"
				break
				;;
			"Kerberos")
				requested_sec="Kerberos"
				sec_name="krb5"
				break
				;;
			"Default")
				requested_sec="NTLMv2"
				break
				;;
			*) echo invalid option;;
		esac
	done


	supported_sec=$(echo $PROTOCOLSETTINGS | sed 's/,/\n/g' | grep "smbAuthenticationMethods" | awk -F\" '{print $(NF-1)}' | sed 's/;/ /g')

	if [[ " $supported_sec " = *" $requested_sec "* ]]; then
		print_log "Requested security Authentication $requested_sec is supported by server" "info"
		check_kereros_ticket_enc $requested_sec
	else
		print_log "Requested security Authentication $requested_sec is not present in azure server supported versions:$supported_sec" "error"
		print_log "Please enable $requested_sec in azure portal https://docs.microsoft.com/en-us/azure/storage/files/files-smb-protocol?tabs=azure-portal#smb-security-settings" "error"
		exit 1
	fi
}

validate_channel_encryption_settings()
{
	print_log "Validating Channel encryption settings"
	supported_enc=$(echo $PROTOCOLSETTINGS | sed 's/,/\n/g' | grep "smbChannelEncryption" | awk -F\" '{print $(NF-1)}' | sed 's/;/ /g')

	if [ $requested_ver = "SMB3.1.1" ]; then
		default_enc="AES-128-GCM"
		if [[ " $supported_enc " = *" $default_enc "* ]]; then
			print_log "$default_enc Channel encryption supported by server for 3.1.1" "info"
		elif  [[ " $supported_enc " = *" AES-256-GCM "* ]]; then
			print_log "AES-256-GCM is supported by server for 3.1.1, but you should install cifs module on client with module parameter 'require_gcm_256' to use AES-256-GCM" "warning"
		elif [[ " $supported_enc " = " AES-128-CCM " ]]; then
			print_log "AES-128-CCM not supported with Azure SMB 3.1.1, Please enable other encryption mechanisms using https://docs.microsoft.com/en-us/azure/storage/files/files-smb-protocol?tabs=azure-portal#smb-security-settings" "error"
			exit 1
		else
			print_log "Unknown Encryption mechanism" "error"
			exit 1
		fi

	elif [[ "$requested_ver" == "SMB3.0" ]]; then
		default_enc="AES-128-CCM"
		if [[ " $supported_enc " = *" $default_enc "* ]]; then
			print_log "$default_enc Channel encryption is supported by server" "info"
		else
			print_log "Requested Channel encryption is not supported $default_enc, Available channel encryptions are $supported_enc" "info"
			print_log "Please enable $default_enc in server configurations or choose different SMB version" "info"
			exit 1
		fi
	fi
}

check_kereros_ticket_enc()
{
	supported_kerb_ticket_enc=$(echo $PROTOCOLSETTINGS | sed 's/,/\n/g' | grep "smbKerberosTicketEncryption" | awk -F\" '{print $(NF-1)}' | sed 's/;/ /g')

	if [ $1 = "Kerberos" ]; then
		print_log "Make sure you have kerbros ticket with one of the following encryption:$supported_kerb_ticket_enc" "info"
		print_log "Server and Client configurations have been validated for Kerbros, Please mount share using appropriate options" "info"
		exit 1
	fi
}

validate_server_cfg()
{
	if [ "$VALIDATESRVCFG" -eq 0 ]; then

		#Check if azure cli is installed on system
		az --version > /dev/null 2>&1
		retVal=$?
		if [ $retVal -ne 0 ]; then
			print_log "Install az cli using  https://docs.microsoft.com/en-us/cli/azure/install-azure-cli and try again" "info"
			exit 1
		fi

		#Check if user has already logged into azure cli
		az account show  > /dev/null 2>&1
		retVal=$?
		if [ $retVal -ne 0 ]; then
			print_log "Please follow the steps to login to azure cli, If you have trouble follow https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli and login manually\n \n"
			rm -f /tmp/azlog.txt
			az login  |& tee -a /tmp/azlog.txt

			cat /tmp/azlog.txt | grep -q "The following tenants require Multi-Factor Authentication (MFA). Use 'az login --tenant TENANT_ID' to explicitly login to a tenant"
			retVal=$?
			if [ $retVal -eq 0 ]; then
				tenantid=`cat /tmp/azlog.txt | grep -wo ' .*-.*-.*-.*-.* ' | xargs`
                                if [ ! -z "$tenantid" ]; then
                                    print_log "Account requires Multi-Factor Authentication. Executing 'az login --tenant $tenantid', Please follow the below steps to authenticate"
                                    az login --tenant $tenantid
                                else
                                    print_log "Account requires Multi-Factor Authentication. Please get the tenant id from azure portal and execute 'az login --tenant TENANTID'"
                                    print_log "Refer this page for more details: https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-how-to-find-tenant#find-tenant-id-through-the-azure-portal"
                                    exit 1
                                fi
			fi
			rm -f /tmp/azlog.txt
		else
			print_log "Already logged into Azure command line interface, please verify details and proceed further"
			az account show
		fi
		print_log "Make sure to logout from az cli using 'sudo az logout' once validations are complete"
		get_server_protocol_settings
		validate_smb_version
		validate_auth_mechanism
		validate_channel_encryption_settings
	fi
}

## When invoking script by sh, it would have syntax error. it happens becuase, by default on ubunntu /bin/sh is mapped to DASH which has many constraints on scripting (e.g. DASH does not support array or select).
## BASH is still default SHELL for SSH. Force to use bash  SHELL now. it does not appear to  impact user expereince a lot.
if [ -z $BASH_VERSION ]; then
        print_log "current SHELL is not BASH. please use bash to run this script" "error"
        exit 1
fi

##  argument # is zero which means user does not specify argument to run the script.
if [ $# -gt 0 ] ; then


	## Detect if system has enhanced getopt
	NEWGETOPT=false
	getopt -T >/dev/null

	if [ $? -eq 4 ]; then
		NEWGETOPT=true
	fi

	SHORT_OPTS=u:a:s:e:h
	LONG_OPTS=uncpath:,storageaccount:,share:,azureenvironment:,help

	## Use getopt to sanitize the arguments first.
	if [ "$NEWGETOPT" ]; then
		ARGS=`getopt --name "$PROG" --long $LONG_OPTS --options $SHORT_OPTS -- "$@"`
	else
		ARGS=`getopt $SHORT_OPTS "$@"`
	fi

	if [ $? != 0 ] ; then
		echo "Usage error (use -h or --help for help)"
		exit 2
	fi

	eval set -- $ARGS

	## Process parsed options
	echo "$@"
	while [ $# -gt 0 ]; do
		case "$1" in
			-u | --uncpath)   UNCPATH="$2"; shift;;
			-a | --account)  ACCOUNT="$2"; shift;;
			-s | --share)  SHARE="$2"; shift;;
			-e | --azureenvironment)  ENVIRONMENT="$2"; shift;;
			-h | --help)
				usage
				exit 0;;
		esac
		shift
	done

	## make sure required options are specified.
	if ( [ -n "$UNCPATH" ] ); then
		print_log  "UNC path option is specified, other options will be ignored (use -h or --help for help)" "warning"
		UNCPATH=$(echo "$UNCPATH" | sed    's/\\/\//g')
		SAFQDN=$(echo "$UNCPATH" | sed 's/[\/\\]/ /g' | awk '{print $1}' )
		ACCOUNT=$(echo "$SAFQDN" | cut -d '.' -f1 )

	elif  ( [ -z "$UNCPATH" ] && (  [ -n "$ACCOUNT" ]  && [  -n "$SHARE" ] && [ -n "$ENVIRONMENT" ] ) ); then

		print_log  "Form the UNC path based on the options specified" "info"

		ACCOUNT=${ACCOUNT,,}
		SHARE=${SHARE,,}
		ENVIRONMENT=${ENVIRONMENT,,}

		SUFFIX=''
		case "$ENVIRONMENT" in
			azurecloud) SUFFIX='.file.core.windows.net' ;;
			azurechinacloud) SUFFIX='.file.core.chinacloudapi.cn' ;;
			azureusgovernment) SUFFIX='.file.core.usgovcloudapi.net' ;;
			azuregermancloud) SUFFIX='.file.core.cloudapi.de' ;;
		esac
		SAFQDN="$ACCOUNT""$SUFFIX"
		UNCPATH="//""$SAFQDN""/""$SHARE"

	else
		print_log  "$PROG: missing options (use -h or --help for help)"  "error"
		exit 2
	fi

fi


## ================================Client Side Environment validation =======================================

## simple function to compare version,echo has different implementatoin in SHELL, use printf to avoid compatability issue.
ver_gt() { test "$(printf  "$1\n$2"  | sort -V | head -n 1)" != "$1"; }
ver_lt() { test "$(printf  "$1\n$2"  | sort -V | head -n 1)" != "$2"; }


LOGDIR="MSFileMountDiagLog"
if [ ! -d "$LOGDIR" ]; then
	mkdir "$LOGDIR"
fi

print_log "Create a folder MSFileMountDiagLog to save the script output"


## Verify Linux distribution version. There is a list of recommended images for use
DISTNAME=''
DISTVER=''
KERVER=''

command -v lsb_release >/dev/null 2>&1  && DISTNAME=$(lsb_release -i | cut -d : -f 2) || DISTNAME=$(cat /etc/*release | grep \\bNAME= | cut -d = -f 2)
command -v lsb_release >/dev/null 2>&1  && DISTVER=$(lsb_release -r |  grep -o  [0-9\\.]\\+ )  || DISTVER=$(cat /etc/*release | grep \\bVERSION_ID= | grep -o  [0-9\\.]\\+)

KERVER=$(uname -r | cut -d - -f 1)
KERVEREXTRA=$(uname -r)

#Trim the whitespace
DISTNAME=$(echo $DISTNAME)
DISTVER=$(echo $DISTVER)
KERVER=$(echo $KERVER)
KERVEREXTRA=$(echo $KERVEREXTRA)

print_log "Client running with $DISTNAME version $DISTVER, kernel version is $KERVEREXTRA"

case $DISTNAME  in
	*Redhat* )
		if ( ver_lt $DISTVER '8' ); then
			print_log "We recommend running following Linux Distributions: Ubuntu Server 18.04+ | RHEL 8+ | CentOS 7.6+ | Debian 9 | openSUSE 15+ | SUSE Linux Enterprise Server 15, please refer to https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-linux for more information" "warning"
		fi
		#kernel version check
		if ( ! ver_lt $DISTVER '8' ); then
			if ( ver_lt $KERVER '4.18.0'); then
				print_log "For RHEL 8, we recommend running Kernel with version 4.18.0+" "warning"
			fi
		fi
		;;

	*CentOS* )
		if ( ver_lt $DISTVER '7.6' ); then
			print_log "We recommend running following Linux Distributions: Ubuntu Server 18.04+ | RHEL 8+ | CentOS 7.6+ | Debian 9 | openSUSE 15+ | SUSE Linux Enterprise Server 15, please refer to https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-linux for more information" "warning"
		fi

		#kernel version check
		if ( ver_gt $DISTVER '7.5' ); then
			if ( ver_lt $DISTVER '7.7' ); then
				if ( ver_lt $KERVER '3.10.0'); then
					print_log "For CentOS 7.6, we recommend running Kernel with version 3.10.0+" "warning"
				fi
			fi
		fi
		;;

	*Ubuntu* )
		echo "Current Ubuntu distribution version is:  $DISTVER"
		if ( ver_lt $DISTVER '18.04' ); then
			print_log "We recommend running following Linux Distributions: Ubuntu Server 18.04+ | RHEL 8+ | CentOS 7.6+ | Debian 9 | openSUSE 15+ | SUSE Linux Enterprise Server 15, please refer to https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-linux for more information" "warning"
		fi

		# kernel version check for ubuntu 18.04
		if ( ver_gt $DISTVER '18.03' ); then
			if ( ver_lt $DISTVER '18.05' ); then
				echo "Current Kernel version is: $KERVER"
				if ( ver_lt $KERVER '5.0.0'); then
					print_log "For Ubuntu 18.04, We recommend running Ubuntu Kernel with version 4.18.0+" "warning"
				fi
			fi
		fi

		#kernel version check for ubuntu 19.04
		if ( ver_gt $DISTVER '19.03' ); then
			if ( ver_lt $DISTVER '19.05' ); then
				if ( ver_lt $KERVER '5.0.0'); then
					print_log "For Ubuntu 19.04, we recommend running Ubuntu Kernel with version 5.0.0+" "warning"
				fi
			fi
		fi
		;;

	*openSUSE* )
		if ( ver_lt $DISTVER '15' ); then
			print_log "We recommend running following Linux Distributions: Ubuntu Server 18.04+ | RHEL 8+ | CentOS 7.6+ | Debian 9 | openSUSE 15+ | SUSE Linux Enterprise Server 15, please refer to https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-linux for more information" "warning"
		fi

		#kernel version check
		if ( ! ver_lt $DISTVER '15' ); then
			if ( ver_lt $KERVER '4.12.14'); then
				print_log "For SUSE 15, we recommend running Kernel with version 4.12.14+" "warning"
			fi
		fi
		;;
	*SLES* )
		if ( ver_lt $DISTVER '12' ); then
			print_log "We recommend running following Linux Distributions: Ubuntu Server 14.04+ | RHEL 7+ | CentOS 7+ | Debian 8 | openSUSE 13.2+ | SUSE Linux Enterprise Server 12, please refer to https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-linux for more information" "warning"

		fi
		;;

	*Debian* )
		if ( ver_lt $DISTVER '9' ); then
			print_log "We recommend running following Linux Distributions: Ubuntu Server 18.04+ | RHEL 8+ | CentOS 7.6+ | Debian 9 | openSUSE 15+ | SUSE Linux Enterprise Server 15, please refer to https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-linux for more information" "warning"
		fi

		#kernel version check
		if ( ver_gt $DISTVER '8' ); then
			if ( ver_lt $DISTVER '10' ); then
				if ( ver_lt $KERVER '4.19.0'); then
					print_log "For Debian 9, we recommend running Debian Kernel with version 4.19.0+" "warning"
				fi
			fi
		fi
		;;
esac

## Check if all the dependencies are installed
# iptables nc wget awk dig|host tcpdump
print_log "Check if the dependencies for this script are installed"
for cmd in "iptables" "nc" "wget" "awk" "tcpdump" "mount"; do
	command -v $cmd --help > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		print_log "Some of the script dependencies are missing. Install the following commands, and make sure they are in the executable path: iptables, nc, wget, awk, tcpdump, mount" "error"
		exit 2
	fi
done

# dig or host command needs to be installed
command -v dig --help > /dev/null 2>&1
if [ $? -ne 0 ]; then
	command -v host --help > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		print_log "dig or host command needs to be installed and executable" "error"
		exit 2
	fi
fi
print_log "All dependencies for the script are installed"

# Check if cifs-utils is installed
print_log "Check if cifs-utils is installed"
if [[ ! -f /sbin/mount.cifs ]]; then
	print_log "cifs-utils module is not installed on this client, please refer to https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-linux#prerequisities-for-mounting-an-azure-file-share-with-linux-and-the-cifs-utils-package for more information" "error"
	exit 2
else
	CIFS_UTILS_VERSION=$(mount.cifs -V|cut -d ':' -f 2|tr -d ' ')
	command -v mount.cifs -V > /dev/null 2>&1
	if [ $? -eq 0 ] && ( ver_lt "$CIFS_UTILS_VERSION" "6.8" ); then
		print_log "cifs-utils version $CIFS_UTILS_VERSION is installed. Newer versions are available. It is recommended to upgrade to at least version 6.8"
	else
		print_log  "cifs-utils is already installed on this client" "info"
	fi
fi

# check if keyutils is installed
print_log "Check if keyutils is installed"
if [[ ! -f /sbin/request-key ]]; then
	print_log "Keyutils is NOT installed! " "error"
	exit 2
else
	print_log "Keyutils is already installed!" "info"
fi


## Check if SMB2.1 is supported. According to https://wiki.samba.org/index.php/LinuxCIFSKernel, SMb2.1 is firstly added into Kernel at version 3.7.
print_log "Check if client has at least SMB2.1 support"

ver_lt "$KERVER" "3.7"

if [ $? -eq 0 ]; then
	print_log "System DOES NOT support SMB2.1"  "error"
	exit 2
else
	print_log "System supports SMB2.1" "info"
fi



##  Check if SMB3 encryption is supported.
print_log "Check if client has SMB 3 Encryption support "

## Ubuntu OS checks the distribution version
if echo "$DISTNAME" | grep Ubuntu >/dev/null 2>&1 ; then
	ver_lt "$DISTVER" "16.04"
	if [ $? -eq 0 ] ; then
		print_log "System DOES NOT support SMB version 3 " "warning"
		SMB3=1
	else
		print_log "System supports SMB version 3" "info"
		SMB3=0
	fi

elif echo "$DISTNAME" | grep SLES >/dev/null 2>&1; then
	ver_lt "$DISTVER" "12.2"
	if [ $? -eq 0 ] ; then
		print_log "System DOES NOT support SMB version 3 " "warning"
		SMB3=1
	else
		print_log "System supports SMB version 3" "info"
		SMB3=0
	fi
	## Other distributions check kernel versions.
else
	ver_lt "$KERVER" "4.11"

	if [ $? -eq 0 ]; then
		print_log "System DOES NOT support SMB version 3 "  "warning"
		SMB3=1
	else
		print_log "System supports SMB version 3 " "info"
		SMB3=0
	fi
fi

#Check if kernel supports SMB v3.1.1
ver_lt "$KERVER" "4.17"
if [ $? -eq 0 ]; then
	SMB311=1
else
	SMB311=0
	print_log "System supports SMB version 3.1.1" "info"
fi

## Check if system has fix for known idle timeout/reconnect issues, not terminate error though.
print_log "Check if client has been patched with the recommended kernel update for idle timeout issue"
if ( ver_gt "$KERVER" "4.9.99" ); then
	print_log "Kernel has been patched with the fixes that prevent idle timeout issues" "info"
else
	print_log "Kernel has not been patched with the fixes that prevent idle timeout issues, more information, please refer to https://docs.microsoft.com/en-us/azure/storage/storage-troubleshoot-linux-file-connection-problems#mount-error112-host-is-down-because-of-a-reconnection-time-out" "warning"
fi

## Prompt user for UNC path if no options are provided.
print_log "Check if client has any connectivity issue with storage account"
if  [ -z "$SAFQDN" ]; then
	ACCOUNT=''
	while [ -z "$ACCOUNT" ];
	do
		print_log "Type the storage account name, followed by [ENTER]:"  'info'
		read ACCOUNT
	done

	SHARE=''
	while [ -z "$SHARE" ];
	do
		print_log "Type the share name, followed by [ENTER]:" "info"
		read SHARE
	done

	print_log "Choose the Azure Environment:"  "info"
	PS3='Please enter your choice: '
	SUFFIX=''
	## SH points to /bib/dash on ubuntu system, but dash does not support array/select.
	options=('azurecloud' 'azurechinacloud' 'azuregermancloud' 'azureusgovernment')

	select opt in "${options[@]}"
	do
		case $opt in
			"azurecloud")
				SUFFIX=".file.core.windows.net"
				break
				;;
			"azurechinacloud")
				SUFFIX=".file.core.chinacloudapi.cn"
				break
				;;
			"azuregermancloud")
				SUFFIX=".file.core.cloudapi.de"
				break
				;;
			"azureusgovernment")
				SUFFIX=".file.core.usgovcloudapi.net"
				break
				;;
			*) echo invalid option;;
		esac
	done
	SAFQDN="$ACCOUNT""$SUFFIX"
	UNCPATH="//""$SAFQDN""/""$SHARE"
fi

print_log "Storage account FQDN is "$SAFQDN"" "info"

## Verify port 445 reachability.

if [ -n "$SAFQDN" ] ; then

	print_log "Getting the Iptables policies"  "info"
	sudo iptables -vnxL | grep DROP >  "./$LOGDIR/firewall-before.txt"

	print_log "Test the storage account IP connectivity over TCP port 445" "info"
	## Netcat is not instaled by default on Redhat/CentOS, so use native BASH command to test the port reachability.
	command -v nc >/dev/null 2>&1  &&  RET=$(nc -v -z -w 5 "$SAFQDN"  445 2>&1) ||  timeout 5 bash -c "echo >/dev/tcp/$SAFQDN/445" && RET='succeeded' || RET="Connection Timeout or Error happens"


	echo "$RET" | grep -i succeeded  >/dev/null 2>&1

	if [ "$?" -eq  0 ] ; then
		print_log "Port 445 is reachable from this client." "info"
	else
		print_log "Port 445 is not reachable from this client and the error is ""$RET"  "error"
		sudo iptables -vnxL | grep DROP >  "./$LOGDIR/firewall-after.txt"
		diff   "./$LOGDIR/firewall-before.txt"   "./$LOGDIR/firewall-after.txt"
		if [[ $? -gt 0 ]];then
			print_log "Iptables has some rules dropping the packets when connecting to Azure Storage Account over TCP port 445." "warning"
		fi
		exit 2
	fi
fi


## Verify  IP region if SMB encrytion is not supported.
if [ "$SMB3" -eq 1 ]; then

	## Get IP range function
	get-ip-region()
	{

		#constant file name
		xmlfile="azurepubliciprange.xml"

		if [ ! -f "./$LOGDIR/$xmlfile" ]; then

			#get the download file  link from the html file
			wget -U firefox -qO  "./$LOGDIR/download.html"  "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653"
			RET=$(cat "./$LOGDIR/download.html"  | grep -o 'https://download\.microsoft\.com[a-zA-Z0-9_/\-]*\.xml' | head -n 1)


			#download the file into local file
			#print_log 'Downloading Azure Public IP range XML file' "info"
			wget -U firefox -qO "./$LOGDIR/$xmlfile"  "$RET"
		fi

		## some Linux distributions do no have GNU version AWK installed. MAWK does not support bitwise operation. Use a bash version as a workaround although it is a bit slower than gawk.     
		IPREGION=''
		awk -V >/dev/null 2>&1 

		if [[ $? -eq 0 ]]; then

			IPREGION=$(cat "./$LOGDIR/$xmlfile"  | awk -v ipaddr="$1" '

			#function to verify if IP network address matches with the IP range
			function IpInRange(iprange, ipaddr)
			{
				split(iprange, a, "/")
				subnetaddr=a[1]
				cidrlen=a[2]

				tmp=32-cidrlen
				ipmax=lshift(1,32)-1
				mask=and((compl(lshift(1,tmp)-1)),ipmax)

				split(ipaddr, b, ".")
				ipnetdec = (b[1] * 16777216) + (b[2] * 65536) + (b[3] * 256) + b[4]
				ipnetdec = and(ipnetdec, mask)

				split(subnetaddr, b, ".")
				subnetdec = (b[1] * 16777216) + (b[2] * 65536) + (b[3] * 256) + b[4]

				return (subnetdec == ipnetdec)
			}
			BEGIN{ region = "" }
			/Region Name/ { split($0, a, "\""); region=a[2]}
			/IpRange/ {split($0, a, "\""); ret=IpInRange(a[2], ipaddr); if (ret) {print  region} }
			') 

		else

			subnet=''
			region==''
			ipaddr="$1"


			while IFS= read -r var
			do
				if  [[ $var =~  'Region Name' ]]; then
					a=(${var//\"/ })
					region=${a[2]}
				fi

				cidraddr=''

				if [[ $var =~ 'IpRange Subnet' ]]; then
					a=(${var//\"/ })
					cidraddr=${a[2]}

				fi

				if [[ -n "$cidraddr" ]]; then

					a=(${cidraddr/\// })
					subnet=${a[0]}
					cidrlen=${a[1]}
					let "tmp=1<<(32-$cidrlen), tmp--"
					let "fullone=1<<32 , fullone--"
					let "mask=$tmp ^ $fullone"
					a=(${ipaddr//./ })
					let "ipnetdec=${a[0]} * 16777216 + ${a[1]} * 65536 + ${a[2]} * 256 + ${a[3]}"
					a=(${subnet//./ })
					let "subnetdec=${a[0]} * 16777216 + ${a[1]} * 65536 + ${a[2]} * 256 + ${a[3]}"
					let "ipnetdec=$ipnetdec & $mask"

					if [[ $subnetdec -eq $ipnetdec ]]; then 
						match=1
						break
					fi

				fi

			done < "./$LOGDIR/$xmlfile" 


			if [[ $match -eq 1 ]];then

				IPREGION=$region

			fi


		fi

	}


	print_log "Client does not support SMB Encyrption, verifying if client is in the same region as Storage Account"
	DHCP25=''
	PIP=''
	SAIP=''
	ClientIPRegion=''
	SARegion=''

	## verify client is Azure VM or not. On untuntu DHCP lease option can be used to check it but Red Hat does not seem to support it. Use client IP too.
	grep -q unknown-245 /var/lib/dhcp/dhclient.eth0.leases  2>&1
	DHCP245=$?

	command -v dig >/dev/null 2>&1  &&  PIP=$(dig +short myip.opendns.com @resolver1.opendns.com) || PIP=$(host -t a myip.opendns.com resolver1.opendns.com 2>&1  | grep 'has address' | grep -o [0-9]\\+\.[0-9]\\+\.[0-9]\\+\.[0-9]\\+)
	get-ip-region "$PIP"

	ClientIPAddress="$PIP"
	ClientIPRegion="$IPREGION"

	if (  [  "$DHCP245" -eq 0 ]  || [  "$ClientIPRegion" != '' ] ); then
		print_log "Client is Azure VM with public IP: $ClientIPAddress, is running in region: $ClientIPRegion" "info"

		command -v dig >/dev/null 2>&1  &&  SAIP=$(dig +short "$SAFQDN" | grep -o [0-9]\\+\.[0-9]\\+\.[0-9]\\+\.[0-9]\\+  ) || SAIP=$(host -t a "$SAFQDN"  2>&1  | grep 'has address' | grep -o [0-9]\\+\.[0-9]\\+\.[0-9]\\+\.[0-9]\\+)
		get-ip-region "$SAIP"

		SAIPAddress="$SAIP"
		SARegion="$IPREGION"
		print_log "Storage account resolved to IP: $SAIPAddress, Region: $SARegion" "info"
		if [ "$SARegion" != "$ClientIPRegion" ] ; then
			print_log "Azure VM region ($ClientIPRegion) mismatches with Storage Account Region ($SARegion), Please make sure Azure VM is in the same region as the storage account. \nMore information, please refer to https://docs.microsoft.com/en-us/azure/storage/storage-how-to-use-files-linux " "error"
			exit 2
		fi
	else
		print_log "Client VM (public IP: $ClientIPAddress) is not Azure VM running in the same region as the storage account. \nMount will fail. For more information, please refer to https://docs.microsoft.com/en-us/azure/storage/storage-how-to-use-files-linux" "error"
		exit 2
	fi

fi




## Prompt user to select server configurations validation
print_log "Script has validated client configurations"
print_log "Do you want to validate azure portal file share settings with client configurations, You will have to authenticate your storage account to read and validate configurations " "info"

options=("yes" "no")
select opt in "${options[@]}"
do
        case $opt in
                yes)
                        #comform to BASH, 0 means true.
                        VALIDATESRVCFG=0
                        break
                        ;;
                no)
                        VALIDATESRVCFG=1
                        break
                        ;;
                *) echo please type 1 or 2;;
        esac
done


if [ "$VALIDATESRVCFG" -eq 0 ]; then
        validate_server_cfg
        print_log "Script has vaidated the server configurations" "info"
fi



## ==============================map drive for user, start tcpdump in background.=======================================

## Function to Enable  CIFS debug logs including packet trace and CIFS kernel debug trace.
enable_log()
{

	TCPLOG="./""$LOGDIR""/packet.cap"
	if [ -f "$TCPLOG" ] ; then
		rm -f "$TCPLOG"
	fi
	CIFSLOG="./""$LOGDIR""/cifs.txt"

	if [ -f "$CIFSLOG" ] ; then
		rm -f "$CIFSLOG"
	fi


	command="tcpdump -i any port 445  -w ""$TCPLOG"" >/dev/null 2>&1 &"
	sudo sh -c  "$command"
	command="echo 'module cifs +p' > /sys/kernel/debug/dynamic_debug/control;echo 'file fs/cifs/* +p' > /sys/kernel/debug/dynamic_debug/control; modprobe cifs;echo 1 > /proc/fs/cifs/cifsFYI"
	sudo sh -c  "$command"
}


## Function to disable logging.
disable_log()
{
	sudo pkill -f "tcpdump -i any port 445 -w "$TCPLOG""

	command="echo 'module cifs -p' > /sys/kernel/debug/dynamic_debug/control;echo 'file fs/cifs/* -p' > /sys/kernel/debug/dynamic_debug/control;modprobe cifs;echo 0 > /proc/fs/cifs/cifsFYI"
	sudo sh -c  "$command"
	sudo dmesg -T > $CIFSLOG
}


## Prompt user to select if he wants to map drive or not.

print_log "Do you want to map drive by script?" "info"
options=("yes" "no")

select opt in "${options[@]}"
do
	case $opt in
		yes)
			#comform to BASH, 0 means true.
			break
			;;
		no)
			exit 0
			;;
		*) echo please type 1 or 2;;
	esac
done


## Prompt user to select diagnostics option
print_log "Do you want to turn on diagnostics logs"

options=("yes" "no")

select opt in "${options[@]}"
do
	case $opt in
		yes)
			#comform to BASH, 0 means true.
			DIAGON=0
			break
			;;
		no)
			DIAGON=1
			break
			;;
		*) echo please type 1 or 2;;
	esac
done

## Prompt user to type the local mount point and storage account access key.
mountpoint=''
while [ -z "$mountpoint" ] ; 
do
	print_log "type the local mount point, followed by [ENTER]:"
	read mountpoint
done

eval mountpoint="$mountpoint"

if [ ! -d "$mountpoint" ] ;then
	print_log "mount point "$mountpoint" does not exist, create it now" 'info'
	mkdir -p "$mountpoint"
fi

password=''
while [ -z "$password" ] ;
do
	print_log "Type the storage account access key, followed by [ENTER]:"
	read password
done

password=\'$password\'
username=$( echo "$SAFQDN" | cut -d '.' -f 1)

if [ "$DIAGON" -eq 0 ]; then
	enable_log
fi


command="mount -t cifs "$UNCPATH"  "$mountpoint" -o vers="$smb_ver",username="$username",password=$password,dir_mode=0777,file_mode=0777,sec="$sec_name""
print_log "Try with mounting share using $smb_ver"
print_log "$command" "info"

if [ -f "/tmp/mount.error" ]; then
	rm /tmp/mount.error
fi
sudo sh -c "$command" 2>/tmp/mount.error

if [[ $? -gt 0 ]] ;then
	echo "Fail to mount with $smb_ver"
	cat /tmp/mount.error
	grep "Permission denied" /tmp/mount.error >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		#SMB 3.0, provide hints to Cx
		echo "The Azure file share failed to mount with mount error (13): Permission denied"
		echo "This could be due to a number of reasons."
		echo "To resolve this issue, follow the steps in the Azure Files troubleshooting guide: https://docs.microsoft.com/en-us/azure/storage/files/storage-troubleshoot-linux-file-connection-problems#mount-error13-permission-denied-when-you-mount-an-azure-file-share"
	fi

	# now try to mount with SMB2.1
	command="mount -t cifs "$UNCPATH"  "$mountpoint" -o vers=2.1,username="$username",password=$password,dir_mode=0777,file_mode=0777,sec=ntlmssp"
	print_log "Failed to mount the share with $smb_ver. Try with mounting share using SMB2.1"
	print_log "$command" "info"
	sudo sh -c "$command" 2>/tmp/mount.error
fi

if [[ $? -gt 0 ]];then
	print_log "Mounting share fails" "error"

	grep "Permission denied" /tmp/mount.error >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		#SMB 2.1, provide hints to Cx
		echo "The Azure file share failed to mount with mount error (13): Permission denied"
		echo "This could be due to a number of reasons."
		echo "To resolve this issue, follow the steps in the Azure Files troubleshooting guide: https://docs.microsoft.com/en-us/azure/storage/files/storage-troubleshoot-linux-file-connection-problems#mount-error13-permission-denied-when-you-mount-an-azure-file-share"
	fi
else
	print_log "Mounting share succeeds" "info"
fi

cat /tmp/mount.error

sleep 1

#Logout from az cli
if [[ $VALIDATESRVCFG -eq 0 ]]; then
	print_log "Do you want to logout from az cli" "info"

	options=("yes" "no")
	select opt in "${options[@]}"
	do
		case $opt in
			yes)
				az logout
				break
				;;
			no)
				break
				;;
				*) echo please type 1 or 2;;
		esac
	done
fi

if [ "$DIAGON" -eq 0 ]; then
	disable_log
	print_log "Packet trace/CIFS debugging logs can be found in MSFileMountDiagLog folder" "info"
fi

