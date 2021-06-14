#!/bin/bash
# You may need to change the first line of this script to point to the location of BASH on
# your system.
#
# makepki.sh -- Creates a single or multi-tiered PKI using openssl
# 
# The script will automatically generate openssl.cnf and 5 scripts:
#
# sign.sh       Signs CSRs using the lowest issuing tier CA
# generate.sh   Creates a CSR + private key and signs it using the lowest issuing tier CA
# revoke.sh     Revokes a cert issued by the lowest issuing tier CA
#

VER=22
MAXTIERS=30
MINTIERS=1

# Change key lengths as desired. Use only valid keylengths: 1024,2048,4096 or 8192
ROOTKEYLENGTH=4096
INTERKEYLENGTH=4096
ISSUERKEYLENGTH=2048
CERTKEYLENGTH=2048

# Default Expiration in Years
ROOTEXPYEARS=20
INTEREXPYEARS=20
ISSUEREXPYEARS=15
CERTEXPYEARS=10
CRLEXPYEARS=5

# Default Org and Org Units.  Change here as desired.
# " - <PKI name>" will be appended to DEFAULT_ORG
# where <PKI name> is supplied by user at runtime.
DEFAULT_ORG="Personal CA"
DEFAULT_ORGUNIT0="OU0"
DEFAULT_ORGUNIT1="OU1"
DEFAULT_ORGUNIT2="OU2"

# Default Expiration in Days
ROOTEXP=$(( $ROOTEXPYEARS * 365 ))
INTEREXP=$(( $INTEREXPYEARS * 365 ))
ISSUEREXP=$(( $ISSUEREXPYEARS * 365 ))
CERTEXP=$(( $CERTEXPYEARS * 365 ))
CRLEXP=$(( $CRLEXPYEARS * 365 ))

# Valid signature algorithms
DIGESTS="sha1|sha224|sha256|sha384|sha512"

# Default CA Private Key password (can be overridden at runtime).
DEFAULT_CAPASSWD="password"
CAPASSWD="$DEFAULT_CAPASSWD"
USE_DEFAULT_CAPASSWD=0      
USE_DEFAULT_COMMON_NAMES=0      

# Private Key Passphrase is in this file at each tier
PRIVATE_KEY_PASSPHRASE_FILE="private-key-passphrase.txt"

HOST="$(hostname -s)"

# Placeholder URI for CRL and authority CA certs.  Override this by specifying a different
# one as an argument at runtime.
BASEURI="http://${HOST}/crl"

# Determine OS
OS=$(uname | tr '[:upper:]' '[:lower:]')
case "$OS" in
   *linux* )
      DATE="date"
      OPENSSL=$(which openssl)
   ;;
   *cygwin* )
      DATE="date"
      OPENSSL=$(which openssl)
   ;;
   *bsd* )
      DATE="date -j"
      [ -f "/usr/local/bin/openssl" ] && OPENSSL="/usr/local/bin/openssl" || OPENSSL=$(which openssl)
   ;;
   darwin )
      DATE="date -j"
      OPENSSL=$(which openssl)
   ;;
   * )
      echo
      echo "ERROR: Unknown OS"
      exit 1
esac   

(which "$OPENSSL" 2>&1 >/dev/null) || { echo "Cannot find openssl"; exit 1; }

######################### Functions ############################

#---------------------------------------------------------------

Usage () {
   echo
   echo "Version $VER"
   echo
   echo "Usage: ${0##*/} <ID> <number-of-tiers> $DIGESTS [Authority/CRL-URI-Prefix]" 
   echo
   echo " This script creates a single or multi-tiered Public Key Infrastructure (PKI)"
   echo " using $($OPENSSL version)."
   echo
   echo " <ID> = string identifying this PKI.  Suggestion: Use a short descriptive name"
   echo "        followed by a number to distinguish this PKI from others you might build"
   echo "        on this host.  The ID will be appended to the Organization."
   echo
   echo " <number-of-tiers> = integer between $MINTIERS and $MAXTIERS inclusive.  This is"
   echo "                     the number of tiers you want in your PKI.  The number includes"
   echo "                     the root and issuing tiers."
   echo
   echo " $DIGESTS = Specify which signature algorithm to use."
   echo
   echo " Authority/CRL-URI-Prefix = Optional URL prefix for Authority Information Access and CRL"
   echo "                            distribution point.  If not provided, script will use "
   echo "                            http://$HOST/crl as the prefix."
   echo
   echo " The script will ask if you'd like to override the default passphrase (which is "
   echo " '$DEFAULT_CAPASSWD') used to protect the private key at each CA tier.  You can accept the"
   echo " default or supply your own passphrase for each tier.  Your passphrases can be the"
   echo " the same or different for each CA tier."
   echo
   echo " The script will also ask if you'd like to supply your own Common Name for each CA"
   echo " certificate at each tier.  The default value for each tier is used otherwise."
   echo
   echo " You can change the default key lengths for the CA certs and certs issued by this PKI"
   echo " by editing the corresponding variables near the top of the makepki.sh script."
   echo
   echo " You can change the default Organization and Organization Unit values by editing the"
   echo " corresponding variables near the top of the makepki.sh script.  <ID> will be appended"
   echo " to the Organization to improve the odds of having a unique Organization for this PKI."
   echo 
   exit 1 
}

getText () {

   # INPUT:
   #  $1: If string is "START", ask if user wants to use enter custom text at all
   #  $2: Field Name
   #  $3: Variable Name containing returned text
   #  $4: Variable Name containing returned status
   #  $5: CA Tier Name
   #  $6: SHOW entered text.  Any value other than SHOW will not echo entered text.

   local TIMER=7
   local RESPONSE=""
   local PHRASE1=""
   local PHRASE2=""
   local  __resultvar1=$3
   local  __resultvar2=$4

   if [[ "$1" == "START" ]]
   then
      echo
      read -p "Do you want to supply your own ${2}s for each CA tier? [y/N]" -n 1 -r
      echo  
      if [[ ! $REPLY =~ ^[Yy]$ ]]
      then
         echo "Default ${2}s will be used for each CA tier."  
         eval $__resultvar2="'1'"
         return
      else
         eval $__resultvar2="'0'"
      fi
   fi

   echo
   while :
   do
      echo -n "Enter the desired $2 for the $5 CA certificate (press ENTER to use default): "
      [[ "$6" == "SHOW" ]] && read PHRASE1 || read -s PHRASE1
      echo
      if [[ "$PHRASE1" == "" ]]
      then
         echo "Empty $2 supplied.  Default will be used instead."
         eval $__resultvar1=""
         break
      fi
      echo -n "Enter the same $2 again: "
      [[ "$6" == "SHOW" ]] && read PHRASE2 || read -s PHRASE2
      echo
      if [[ "$PHRASE1" == "$PHRASE2" ]]
      then
         eval $__resultvar1="'$PHRASE1'"
         break
      else
         echo "ERROR: ${2}s do not match.  Try again."
      fi
   done
}

#---------------------------------------------------------------


createMakeIssuingCaScript () {
   # Creates the makeissuinca.sh script in the current directory.
cat > makeissuingca.sh << EOF
#!/usr/bin/env bash

# makeissuingca.sh version $VER -- Creates an additional issuing CA at the same tier as other issuing CAs.

OPENSSL="\$(which openssl)"
MD="sha256"
CERTEXP=$(( $CERTEXPYEARS * 365 ))
CRLEXP=$(( $CRLEXPYEARS * 365 ))

Usage () {
   echo
   echo "Version $VER"
   echo
   echo "Usage: \${0##*/} <common-name>|same [$DIGESTS]"
   echo
   echo " This script creates an additional issuing CA at the tier as the original issuing CA."
   echo
   echo " <common-name>|same   = Specify the common name of this issuing CA, or enter 'same' if you want"
   echo "                      this tier to have the same common name as the original issuing tier"
   echo
   echo " $DIGESTS (Optional) Specify which signature algorithm to use. \$MD will be used if no"
   echo "            digest is provided."
   echo
   exit 1 
}

# Check for the right number of arguments
if ! (( \$# == 1 || \$# == 2 ))
then
   Usage 
fi

ORIGINAL_ISSUING_CACERT="issuingCA/cacert.pem"
if ! [ -f "\$ORIGINAL_ISSUING_CACERT" ]
then
   echo
   echo "ERROR: Unable to locate original Issuing CA cert at \$ORIGINAL_ISSUING_CACERT."
   echo
   Usage
fi

SUBJ=""

case "\$1" in
   same)
      SUBJ="/\$(\$OPENSSL x509 -in "\$ORIGINAL_ISSUING_CACERT" -noout -subject)"
      if [ "x\$SUBJ" == "x" ]
      then
         echo
         echo "ERROR: Unable to extract CN from \$ORIGINAL_ISSUING_CACERT"
         echo
         Usage
      fi
      ;;
   *)   
      CN="\$1"
      if [ "x\$CN" == "x" ]
      then
         echo
         echo "ERROR: Common Name cannot be empty"
         echo
         Usage
      fi
      ;;
esac

if (( \$# == 2 ))
then
   if [[ "\$2" =~ ^($DIGESTS)$ ]] 
   then
      MD="\$2"
   else
      echo
      echo "ERROR: Invalid signature algorithm."
      echo
      Usage
   fi
fi

# Get the CA and CRL making and sign, generate and revoke functions
. $COLLECTION/../makepki-common


STAMP="\$($DATE "+%Y%m%d%H%M%S")"
PREVEXT="$EXT"
EXT="issuingCA\$STAMP"
EXP="$ISSUEREXP"
KEYSIZE="$ISSUERKEYLENGTH"
mkdir -p "\$EXT"
cd "\$EXT"
echo 
echo "Creating new Issuing tier CA \$EXT"
echo "-------------------------------------------------------------"
rootCA_authorityInfoAccess="# authorityInfoAccess = Not Applicable on this CA"
rootCA_crlDistributionPoints="# crlDistributionPoints = Not Applicable on this CA"
interCA_authorityInfoAccess="# authorityInfoAccess = Not Applicable on this CA"
interCA_crlDistributionPoints="# crlDistributionPoints = Not Applicable on this CA"
issuerCA_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/\${PREVEXT}.${DOMAIN}-cert.pem"
issuerCA_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/\${PREVEXT}.${DOMAIN}-crl.pem"
cert_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/\${EXT}.${DOMAIN}-cert.pem"
cert_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/\${EXT}.${DOMAIN}-crl.pem"
issuerCA_pathlen=",pathlen:2"
createConfig
CAPASSWD="$DEFAULT_CAPASSWD"
if [ "x\$CN" != "x" ]
then
   SUBJ="/C=US/ST=WA/O=$DEFAULT_ORG/OU=$DEFAULT_ORGUNIT0/OU=$DEFAULT_ORGUNIT1/OU=$DEFAULT_ORGUNIT2/localityName=Seattle/CN=\$CN/description=\$EXT"
fi
createCA "\$EXT" "\$KEYSIZE" "\$SUBJ" "$COLLECTION" "$DOMAIN" "\$CAPASSWD" "\$EXP"
createCrl "\${EXT}.${DOMAIN}" "\$SUBJ" "$COLLECTION"
# Create sign.sh, the script used to sign CSRs.
createSignScript
# Create generate.sh, the script used to generate and sign certs.
createGenerateScript
# Create revoke.sh, the script used to revoke certs and issue a new CA
createRevokeScript "\${EXT}.${DOMAIN}" ""
# Remove trust-chain.pem and instead create a symlink 
# named trust-chain.pem pointing to $COLLECTION/${DOMAIN}-cacerts.pem
rm trust-chain.pem && ln -s $COLLECTION/${DOMAIN}-cacerts.pem trust-chain.pem
# Make a symlink in the issuingCA directory to the directory containing all CRLs (and CA certs)
ln -s $COLLECTION crls

echo "-------------------------------------------------------------"
echo
echo "Issuing CA \$EXT is ready."
echo "Use the sign.sh, generate.sh, and revoke.sh script in ./\$EXT" 
echo "to sign, generate and revoke certs."
echo 
echo "The COMPLETE trust chain is in trust-chain.pem"
echo

EOF
chmod +x makeissuingca.sh
}


#--------------------------------------------------------------------------

makeCommon () {

  # Creates file containing various scripts common across all CAs in the PKI.

cat > makepki-common << EOF
# Generate openssl.cnf
createConfig () {
   
   #  Creates the openssl.cnf customized for each CA tier.

   cat > openssl.cnf << _EOF
#
# OpenSSL configuration file for \$EXT of PKI ${DIR}.${HOST}.
# Created on $($DATE) by makepki.sh version $VER using $($OPENSSL version).  

# This definition stops the following lines choking if BASEDIR is not
# defined.
HOME = .
RANDFILE  = \\\$ENV::HOME/.rnd

# Extra OBJECT IDENTIFIER info:
#oid_file  = \\\$ENV::HOME/.oid
oid_section  = new_oids

# To use this configuration file with the "-extfile" option of the
# "openssl x509" utility, name here the section containing the
# X.509v3 extensions to use:
# extensions  = 
# (Alternatively, use a configuration file that has only
# X.509v3 extensions in its main [= default] section.)

[ new_oids ]

# We can add new OIDs in here for use by 'ca' and 'req'.
# Add a simple OID like this:
# testoid1=1.2.3.4
# Or use config file substitution like this:
# testoid2=\\\${testoid1}.5.6

####################################################################
[ ca ]
default_ca = CA_default  # The default ca section

####################################################################
[ CA_default ]

dir  = .   # Where everything is kept
#certs  = \\\$dir/certs  # Where the issued certs are kept
certs  = \\\$dir/issuedcerts  # Where the issued certs are kept
crl_dir  = \\\$dir/crl  # Where the issued crl are kept
database = \\\$dir/index.txt # database index file.
unique_subject = no   # Set to 'no' to allow creation of
# several certificates with same subject.
new_certs_dir = \\\$dir/issuedcerts  # default place for new certs.

certificate = \\\$dir/cacert.pem  # The CA certificate
serial  = \\\$dir/serial   # The current serial number
crlnumber = \\\$dir/crlnumber # the current crl number
# must be commented out to leave a V1 CRL
crl  = \\\$dir/crl.pem   # The current CRL
private_key = \\\$dir/cakey.pem # The private key
RANDFILE = \\\$dir/.rand # private random number file

x509_extensions = usr_cert  # The extentions to add to the cert

# Comment out the following two lines for the "traditional"
# (and highly broken) format.
name_opt  = ca_default  # Subject Name options
cert_opt  = ca_default  # Certificate field options

# Extension copying option: use with caution.
copy_extensions = copy

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crlnumber must also be commented out to leave a V1 CRL.
crl_extensions = crl_ext

#default_days = 4000   # how long to certify for
default_days = \$CERTEXP   # how long to certify for
default_crl_days = \$CRLEXP   # how long before next CRL
default_md = \$MD   # which md to use.
preserve = no   # keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy  = policy_match

# For the CA policy
[ policy_match ]
countryName  = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
localityName  = optional
commonName  = supplied
emailAddress  = optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName  = optional
stateOrProvinceName = optional
localityName  = optional
organizationName = optional
organizationalUnitName = optional
commonName  = supplied
emailAddress  = optional
dnQualifier = optional
description = optional
x500UniqueIdentifier = optional

[ policy_identityCert ]
description = required
organizationName = required
organizationalUnitName = optional
countryName  = optional
DC = optional
commonName  = supplied
emailAddress  = optional

[ policy_identityAndSigning ]
DC = optional
description = required
x500UniqueIdentifier = required
commonName  = supplied
organizationalUnitName = optional
organizationName = required
countryName  = optional
dnQualifier = optional

####################################################################
[ req ]
default_bits=\$CERTKEYLENGTH
default_md=\$MD
default_keyfile=privkey.pem
distinguished_name=req_distinguished_name
#attributes=req_attributes
x509_extensions = v3_ca # The extentions to add to the self signed cert

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options. 
# default: PrintableString, T61String, BMPString.
# pkix  : PrintableString, BMPString.
# utf8only: only UTF8Strings.
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: current versions of Netscape crash on BMPStrings or UTF8Strings
# so use this option with caution!
# we use PrintableString+UTF8String mask so if pure ASCII texts are used
# the resulting certificates are compatible with Netscape
string_mask=MASK:0x2002

req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName=Country Name (2 letter code)
countryName_default=US
countryName_min=0
countryName_max=2

stateOrProvinceName=State or Province Name (full name)
stateOrProvinceName_default=WA
stateOrProvinceName_max=64

localityName=Locality Name (eg, city)
localityName_default=Seattle
localityName_max=64

0.organizationName=Organization Name (eg, company)
0.organizationName_default=\$DEFAULT_ORG
0.organizationName_max=64

# we can do this but it is not needed normally :-)

0.organizationalUnitName=Organizational Unit Name (eg, section)
0.organizationalUnitName_default=\$DEFAULT_ORGUNIT0
0.organizationalUnitName_max=64

1.organizationalUnitName=Organizational Unit Name (eg, section)
1.organizationalUnitName_default=\$DEFAULT_ORGUNIT1
1.organizationalUnitName_max=64

2.organizationalUnitName=Organizational Unit Name (eg, section)
2.organizationalUnitName_default=\$DEFAULT_ORGUNIT2
2.organizationalUnitName_max=64

3.organizationalUnitName=Organizational Unit Name (eg, section)
3.organizationalUnitName_default=
3.organizationalUnitName_max=64

x500UniqueIdentifier=Unique Identifier
x500UniqueIdentifier_default= 
x500UniqueIdentifier_max=64

commonName=Common Name (eg, your name or your server\'s hostname)
commonName_max=64
commonName_default=

emailAddress=Email Address
emailAddress_max=64
emailAddress_default=

description=Description
description_max=64
description_default= 

dnQualifier=DN Qualifier
dnQualifier_max=64
dnQualifier_default= 

# SET-ex3   = SET extension number 3

[ req_attributes ]
challengePassword=A challenge password
challengePassword_default=12345678
challengePassword_min=4
challengePassword_max=20

unstructuredName=An optional company name
unstructuredName_default=
unstructuredName_max=64

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType   = server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment   = "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl  = http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints=CA:FALSE
keyUsage=nonRepudiation, digitalSignature, keyEncipherment
#subjectAltName=@alt_names

[ v3_ca ]

# Extensions for a typical CA

# PKIX recommendation.

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
basicConstraints=CA:true

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# keyUsage = cRLSign, keyCertSign

# Some might want this also
# nsCertType=sslCA, emailCA

# Include email address in subject alt name: another PKIX recommendation
# subjectAltName=email:copy
# Copy issuer details
# issuerAltName=issuer:copy

# DER hex encoding of an extension: beware experts only!
# obj=DER:02:03
# Where 'obj' is a standard or added object
# You can even override a supported extension:
# basicConstraints= critical, DER:30:03:01:01:FF

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
#authorityKeyIdentifier=keyid:always,issuer:always
authorityKeyIdentifier=keyid:always

[ crl_distribution ]

fullname=URI:\${BASEURI}/nothing.html

[ proxy_cert_ext ]
# These extensions should be added when creating a proxy certificate

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType=server

# For an object signing certificate this would be used.
# nsCertType=objsign

# For normal client use this is typical
# nsCertType=client, email

# and for everything including object signing:
# nsCertType=client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage=nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment="OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl=http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This really needs to be in place for it to be a proxy certificate.
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

####################################################################
[ rootCA ]
basicConstraints=critical,CA:TRUE\$rootCA_pathlen
subjectKeyIdentifier=hash
keyUsage = critical,keyCertSign,cRLSign,digitalSignature
authorityKeyIdentifier=keyid:always
\$rootCA_authorityInfoAccess
\$rootCA_crlDistributionPoints
nsComment=rootCA
#######################################################################

#######################################################################
[ interCA ]
basicConstraints=critical,CA:TRUE\$interCA_pathlen
subjectKeyIdentifier = hash
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
authorityKeyIdentifier=keyid:always
\$interCA_authorityInfoAccess
\$interCA_crlDistributionPoints
nsComment=interCA
#######################################################################

#######################################################################
[ issuingCA ]
basicConstraints=critical,CA:TRUE\$issuerCA_pathlen
subjectKeyIdentifier = hash
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
authorityKeyIdentifier=keyid:always
\$issuerCA_authorityInfoAccess
\$issuerCA_crlDistributionPoints
nsComment=issuingCA
#######################################################################

######################################################################
[ sslCert ]
basicConstraints=critical,CA:FALSE
subjectKeyIdentifier = hash
keyUsage = critical,digitalSignature,keyEncipherment
authorityKeyIdentifier=keyid,issuer:always
extendedKeyUsage = clientAuth, serverAuth
\$cert_authorityInfoAccess
\$cert_crlDistributionPoints
nsComment=sslCert
######################################################################

######################################################################
[ objectSigningCert ]
authorityKeyIdentifier = keyid
subjectKeyIdentifier = hash
authorityKeyIdentifier=keyid
keyUsage = critical,digitalSignature
\$cert_authorityInfoAccess
\$cert_crlDistributionPoints
nsComment=objectSigningCert
######################################################################

######################################################################
[ clientCert ]
basicConstraints=critical,CA:FALSE
subjectKeyIdentifier = hash
keyUsage = critical,digitalSignature,keyAgreement
authorityKeyIdentifier=keyid,issuer:always
extendedKeyUsage = clientAuth
\$cert_authorityInfoAccess
\$cert_crlDistributionPoints
nsComment=clientCert
######################################################################

######################################################################
[ serverCert ]
basicConstraints=critical,CA:FALSE
subjectKeyIdentifier = hash
keyUsage = critical,digitalSignature,keyEncipherment,keyAgreement
authorityKeyIdentifier=keyid,issuer:always
extendedKeyUsage = serverAuth
\$cert_authorityInfoAccess
\$cert_crlDistributionPoints
nsComment=serverCert
######################################################################

_EOF
}

#----------------------------------------------------------------------------------------------

createCA () {

   # Creates CA cert and key.  Called for each tier in the PKI.

   # INPUTS
   
   # arg1 = CA Certificate Type: <rootCA|interCA|issuerCA>
   # arg2 = keysize: <1024|2048|4096|8192>
   # arg3 = <Subject>
   # arg4 = <common destination directory>
   # arg5 = <Domain>
   # arg6 = <Password for private key>
   # arg7 = <Expiration in days>
   
   # OUTPUTS
   
   # cakey.pem, cacert.pem, trust-chain.pem in current directory
   # copy of cacert.pem in \$arg4 and prepended to all certs file in \$arg4 

   local EXT="\$1"
   local KEYSIZE="\$2"
   local SUBJ="\$3"
   local CN="\$(echo \$SUBJ | tr '/' '\n' | grep CN= | cut -d= -f2- | tr -d [[:space:]])"
   local COLLECTION="\$4"
   local DOMAIN="\$5"
   local CAPASSWD="\$6"
   local EXP="\$7"

   mkdir issuedcerts
   echo 1000 > serial
   touch index.txt
   touch index.txt.attr
   
   echo 
   echo -n "\$EXT   Creating \$KEYSIZE bit private key..."
   \$OPENSSL genrsa -des3 -out cakey.pem -passout pass:"\$CAPASSWD" \$KEYSIZE 2>/dev/null
   [ \$? -eq 0 ] && echo "Done." || { echo "Failed!"; exit 1; }
   chmod 600 cakey.pem
   case "\$EXT" in
      rootCA)
         echo -n "\$EXT   Creating self-signed certificate..."
         \$OPENSSL req -new -batch -x509 -days \$EXP -extensions \$EXT -subj "\$SUBJ" -key cakey.pem -out cacert-tmp.pem1 -config openssl.cnf -passin pass:"\$CAPASSWD"
         [ \$? -eq 0 ] && echo "Done." || { echo "Failed!"; exit 1; }
	      \$OPENSSL x509 -in "cacert-tmp.pem1" -setalias "\${EXT}" -out cacert-tmp.pem2
	      \$OPENSSL x509 -in "cacert-tmp.pem2" -clrtrust -out cacert.pem
	      rm -f "cacert-tmp.pem1"
	      rm -f "cacert-tmp.pem2"
         cp cacert.pem \$COLLECTION/\${EXT}.\${DOMAIN}-cert.pem
         cp cacert.pem \$COLLECTION/\${DOMAIN}-cacerts.pem
	      cp cacert.pem trust-chain.pem
	      echo "\$CAPASSWD" > $PRIVATE_KEY_PASSPHRASE_FILE
         chmod 600 $PRIVATE_KEY_PASSPHRASE_FILE
         ;;
      *)
         echo -n "\$EXT   Creating certificate request..."
	      #\$OPENSSL req -new -batch -key cakey.pem -subj "\$(echo -n "\$SUBJ" | tr "\n" "/")" -out \${CN}-csr.pem -config openssl.cnf -passin pass:"\$CAPASSWD" 2>/dev/null
	      \$OPENSSL req -new -batch -key cakey.pem -subj "\$SUBJ" -out \${CN}-csr.pem -config openssl.cnf -passin pass:"\$CAPASSWD" 2>/dev/null
	      [ \$? -eq 0 ] && echo "Done." || { echo "Failed!"; exit 1; }
	      echo "\$CAPASSWD" > $PRIVATE_KEY_PASSPHRASE_FILE
         chmod 600 $PRIVATE_KEY_PASSPHRASE_FILE
	      cd ..
         echo -n "\$EXT   Signing certificate request with \${PREVEXT} certificate..."
         CAPASSWD="\$(cat $PRIVATE_KEY_PASSPHRASE_FILE)"
	      \$OPENSSL ca -batch -policy policy_anything -extensions "\$(echo -n "\$EXT" | sed 's/[0-9]*//g')" -days \$EXP -out \${EXT}/\${CN}-cert.pem1 -in \${EXT}/\${CN}-csr.pem -config \${EXT}/openssl.cnf -subj "\$SUBJ" -passin pass:"\$CAPASSWD" 2>/dev/null
         [ \$? -eq 0 ] && echo "Done." || { echo "Failed!"; exit 1; }
         cd "\$EXT" 
	      \$OPENSSL x509 -in "\${CN}-cert.pem1" -setalias "\${EXT}" -out "\${CN}-cert.pem2"
	      \$OPENSSL x509 -in "\${CN}-cert.pem2" -clrtrust -out cacert.pem
	      rm -f "\${CN}-cert.pem1"
	      rm -f "\${CN}-cert.pem2"
	      cp cacert.pem \$COLLECTION/\${EXT}.\${DOMAIN}-cert.pem
         cat cacert.pem \$COLLECTION/\${DOMAIN}-cacerts.pem > \$COLLECTION/\${DOMAIN}-cacerts.tmp && mv \$COLLECTION/\${DOMAIN}-cacerts.tmp \$COLLECTION/\${DOMAIN}-cacerts.pem
	      cp \$COLLECTION/\${DOMAIN}-cacerts.pem trust-chain.pem
         ;;
   esac
}

#----------------------------------------------------------------------------------------------

createCrl () {

   # Creates the CRL for each tier in the PKI.

   # INPUTS

   # arg1 = CA Certificate Type: <rootCA|inter..CA|issuerCA>
   # arg2 = <Subject>
   # arg3 = <Common-Destination>
   
   # OUTPUTS

   # crlnumber file and CRL file in current directory.
   # CRL file in the \$arg3 directory

   local EXT="\$(echo "\$1" | cut -d. -f1)"
   local SUBJ="\$2"
   local CN="\$(echo "\$SUBJ" | tr '/' '\n' | grep CN= | cut -d= -f2- | tr -d [[:space:]])"
   local DEST="\$3"
   local CAPASSWD="\$([ -s $PRIVATE_KEY_PASSPHRASE_FILE ] && cat $PRIVATE_KEY_PASSPHRASE_FILE || echo "")"
   mkdir -p crl
   echo 1000 > crlnumber
   
   echo -n "\$EXT   Creating CRL..."
   \$OPENSSL ca -gencrl -keyfile cakey.pem -cert cacert.pem -out crl/\${1}-crl.tmp -config openssl.cnf -passin pass:"\$CAPASSWD" 2>/dev/null
   [ \$? -eq 0 ] && echo "Done." || { echo "Failed!"; exit 1; }
   local NEXTUPDATE="\$(\$OPENSSL crl -in crl/\${1}-crl.tmp -noout -nextupdate | cut -d= -f2 | tr -s ' ')"
   local CRLNUM="\$(\$OPENSSL crl -in crl/\${1}-crl.tmp -noout -crlnumber | cut -d= -f2)"
   local CRLFILE="crl\${CRLNUM}-\${1}-Exp_\$(echo "\$NEXTUPDATE" | tr ' :' '_')-crl"
   cp -f crl/\${1}-crl.tmp crl/\${CRLFILE}.pem
   cp -f crl/\${1}-crl.tmp crl/\${CRLFILE}-EMPTY.pem
   rm -f crl/\${1}-crl.tmp
}

#----------------------------------------------------------------------------------------------

createSignScript () {

  # Creates the sign.sh script.

  cat > sign.sh << EOF_sign
#!/usr/bin/env bash

# sign.sh version $VER -- signs CSRs

OPENSSL="\$(which openssl)"

ORG="$DEFAULT_ORG"

Usage () {
   echo
   echo "Version $VER"
   echo
   echo "Usage: \\\${0##*/} client|server|ssl|signing <CSR-file> [<private-key-file>] [(now|<start-date>):<end-date>] [$DIGESTS]" 
   echo
   echo " This script signs a CSR as the cert type specified (creating PEM and DER cert files) and"
   echo " optionally creates a p12 file if private-key-file is supplied.  The p12 file"
   echo " contains the certificate, private key and trust chain."
   echo
   echo " Enter the type of certificate desired, where:"
   echo
   echo " server             = keyUsage = critical,digitalSignature,keyEncipherment,keyAgreement; extendedKeyUsage = serverAuth"
   echo " client             = keyUsage = critical,digitalSignature,keyAgreement; extendedKeyUsage = clientAuth"
   echo " ssl                = keyUsage = critical,digitalSignature,keyEncipherment; extendedKeyUsage = clientAuth, serverAuth"
   echo " signing            = keyUsage = critical,digitalSignature"
   echo
   echo " <CSR-file>                 = name of the BASE64 (PEM) file containing the CSR"
   echo
   echo " <private-key-file>         = (optional) is the file containing the private key for this."
   echo "                              CSR. Provide this if a P12 (cert+key+chain) is desired."
   echo
   echo " <start-date>:<end-date>    = (optional) Desired certificate start validity date in YYMMDDhhmmss"
   echo "                              format, or use 'now' for the current date/time, followed by colon ':'"
   echo "                              then the desired certificate end validity date in YYMMDDhhmmss"
   echo "                              format.  Dates after December 31, 2049 23:59:59 will be capped at"
   echo "                              that date to prevent OpenSSL from using dates in the previous century."
   echo
   echo " $DIGESTS (optional) Override the openssl.cnf default signature algorithm with this value."
   echo
   echo " If no dates are supplied, the start date will be current date and the end date"
   echo " will be $CERTEXP days from now."
   exit 1
}

checkHash () {

   CSRHASH=\\\$(\\\$OPENSSL req -in "\\\$1" -modulus -noout | \\\$OPENSSL md5)
   KEYHASH=\\\$(\\\$OPENSSL rsa -in "\\\$2" -modulus -noout | \\\$OPENSSL md5)

   # Is the supplied key for the supplied CSR?
   [ "\\\$CSRHASH" == "\\\$KEYHASH" ] && return 0 || return 1

}

createP12 () {

   # arg1 = Path and file to PEM cert
   # arg2 = Private key

   FILENOEXT=\\\${1%\\\.*}

   ALIAS=\\\$(\\\$OPENSSL x509 -in "\\\$1" -noout -alias)
   \\\$OPENSSL pkcs12 -export -out "\\\${FILENOEXT}.p12" -inkey "\\\$2" -in "\\\$1" -certfile "trust-chain.pem" -name "\\\$ALIAS" -passout pass:password 
   if [ \\\$? -eq 0 ]
   then
      echo "P12 file: \\\${FILENOEXT}.p12.  Passphrase is 'password'."
      echo "(P12 file contains cert, private key, and trust chain.)"
      echo
   else
      echo
      echo "Failed to create P12 file."
      echo
   fi
}

sign () {
   # arg1 = certificate type desired
   # arg2 = path/file containing CSR
   # arg3 = subject (to use in certificate)
   # arg4 = private key file.  If key file is not empty, this function will create a P12.
   # arg5 = Start and end date/time for certficate validity
   # arg6 = signature algorithm
   
   local CAPASSWD="\\\$([ -s $PRIVATE_KEY_PASSPHRASE_FILE ] && cat $PRIVATE_KEY_PASSPHRASE_FILE || echo "")"
   
   CSRFILE="\\\${2##*/}"
   CERTFILENOEXT="\\\$(echo "\\\${CSRFILE%\\\.*}" | tr '[A-Z]' '[a-z]' | sed -e 's/csr/cert/g')"
   [ "\\\$CSRFILE" == "\\\$CERTFILENOEXT" ] && CERTFILENOEXT="\\\$CERTFILENOEXT-cert"
   DIR="\\\$1"
   mkdir -p "\\\$DIR"
   cp "\\\$2" "\\\$DIR/"
   
   NEWDATES="\\\$5"

   [ -z "\\\$6" ] && md="" || md="-md \\\$6"

   if [ -z "\\\$3" ]
   then # Empty subject string supplied
      \\\$OPENSSL ca -batch -policy policy_anything \\\$md -extensions \\\$1 -out "\\\${DIR}/\\\${CERTFILENOEXT}-temp.pem1" -in "\\\${DIR}/\\\$CSRFILE" \\\$NEWDATES -config openssl.cnf -passin pass:"\\\$CAPASSWD"
   else # Subject string supplied
      \\\$OPENSSL ca -batch -policy policy_anything \\\$md -extensions \\\$1 -out "\\\${DIR}/\\\${CERTFILENOEXT}-temp.pem1" -in "\\\${DIR}/\\\$CSRFILE" \\\$NEWDATES -config openssl.cnf -subj "\\\$(echo -n \\\$3)" -passin pass:"\\\$CAPASSWD"
   fi
   if [ \\\$? -eq 0 ]
   then
      if [ ! -z "\\\$NEWDATES" ]
      then
         echo
         echo "NOTE:  Some versions of OpenSSL display an incorrect number of days before the certificate expires (above) when the start"
         echo "       and/or end dates are overridden.  The certificate expiration date shown is correct - the incorrect"
         echo "       number of days is only a display error in some versions of openssl."
      fi
      SERIAL="serial\\\$(echo \\\$(\\\$OPENSSL x509 -in "\\\${DIR}/\\\${CERTFILENOEXT}-temp.pem1" -noout -serial) | cut -d= -f2)"
      cat "\\\${DIR}/\\\${CERTFILENOEXT}-temp.pem1" | \\\$OPENSSL x509 | \\\$OPENSSL x509 -setalias "\\\$1" -out "\\\${DIR}/\\\${CERTFILENOEXT}-temp.pem2"
      \\\$OPENSSL x509 -in "\\\${DIR}/\\\${CERTFILENOEXT}-temp.pem2" -clrtrust -out "\\\${DIR}/\\\${SERIAL}-\\\${CERTFILENOEXT}.pem"
      rm -f "\\\${DIR}/\\\${CERTFILENOEXT}-temp.pem1"
      rm -f "\\\${DIR}/\\\${CERTFILENOEXT}-temp.pem2"
      \\\$OPENSSL x509 -in "\\\${DIR}/\\\${SERIAL}-\\\${CERTFILENOEXT}.pem" -inform PEM -out "\\\${DIR}/\\\${SERIAL}-\\\${CERTFILENOEXT}.cer" -outform DER
      echo
      echo "Base 64 (PEM) certificate: \\\${DIR}/\\\${SERIAL}-\\\${CERTFILENOEXT}.pem"
      echo "Binary (DER) certificate: \\\${DIR}/\\\${SERIAL}-\\\${CERTFILENOEXT}.cer"
      echo "Trust chain is in trust-chain.pem."
      echo
      if [ -f "\\\$4" ]
      then
         # Private key file provided.  If it's valid, create a p12.
         checkHash "\\\$2" "\\\$4"
         [ \\\$? -eq 0 ] && createP12 "\\\${DIR}/\\\${SERIAL}-\\\${CERTFILENOEXT}.pem" "\\\$4" || echo "Private key provided does not match supplied CSR.  p12 not created."
      fi
   else
      echo
      echo "ERROR: Failed to sign certificate request."
      echo
      exit 1
   fi
}

function newDates() 
{
   # Converts supplied date string into proper openssl
   # startdate and enddate arguments.
   #
   # arg1: <startdate>:<enddate>

   ENDDATE=\\\$(echo "\\\$1" | cut -d':' -f2)
   if [[ \\\$1 =~ ^[nN][oO][wW] ]]
   then 
      STARTDATE="\\\$($DATE "+%y%m%d%H%M%S")"
   else
      STARTDATE=\\\$(echo "\\\$1" | cut -d':' -f1)
   fi

   # Cap date at December 31, 2049, else it rolls over to last century
   [ \\\$STARTDATE -gt 491231235959 ] && STARTDATE="491231235959"
   [ \\\$ENDDATE -gt 491231235959 ] && ENDDATE="491231235959"

   if [ \\\$STARTDATE -lt \\\$ENDDATE ]
   then 
      echo "-startdate \\\${STARTDATE}Z -enddate \\\${ENDDATE}Z"
   else
      echo ""
   fi
}

# Check for the right number of arguments
if ! (( \\\$# == 2 || \\\$# == 3 || \\\$# == 4 || \\\$# == 5 ))
then
   Usage 
fi

TYPE="\\\$1"

# Does CSR file exist?
if [ ! -f "\\\$2" ]
then
   echo
   echo "CSR file \\\$2 not found."
   echo
   Usage
else
   CSRFILE="\\\$2"
fi

# Are there optional arguments?
KEY=""
NEWDATES=""
MD=""
if (( \\\$# >= 3 ))
then
   shift 2
   for i in "\\\$@"
   do
      if [ -f "\\\$i" ]
      then
         KEY="\\\$i"
      elif [[ \\\$i =~ ^([0-9]{12}|[nN][oO][wW]):[0-9]{12} ]] && [[ -z "\\\$NEWDATES" ]]
      then # ith argument is a date.
         NEWDATES="\\\$(newDates \\\$i )"  
         if [ -z "\\\$NEWDATES" ]
         then
            echo; echo "ERROR: Start date is after or equal to end date"; echo; exit 1
         fi
      elif [[ \\\$i =~ ^($DIGESTS)$ ]] && [[ -z "\\\$MD" ]]
      then # ith argument is signature algorithm
         MD="\\\$i"
      else
         echo
         echo "Key file does not exist or date is not in YYMMDDhhmmss:YYMMDDhhmmss or"
         echo "now:YYMMDDhhmmss format or incorrect signature algorithm provided or"
         echo "the same argument type was provided more than once."
         echo
         exit 1
      fi
   done
fi

# Is file a valid CSR?
\\\$OPENSSL req -noout -verify -in "\\\$CSRFILE"
if [ \\\$? -ne 0 ]
then
   echo
   echo "ERROR: CSR file \\\$CSRFILE is invalid."
   echo 
   if (\\\$OPENSSL version | grep -qci fips)
   then
      echo "Some FIPS versions of OpenSSL may not accept an MD5 signature algorithm."
      echo 
      echo -n "You are using: "
      \\\$OPENSSL version
      echo 
      echo "Your CSR:"
      echo
      \\\$OPENSSL req -noout -text -in "\\\$CSRFILE"
   fi
   echo
   exit 1
fi

SUBJ="\\\$(echo "\\\$(\\\$OPENSSL req -in "\\\$CSRFILE" -noout -subject)" | cut -d= -f2-)"
if ! [[ \\\$SUBJ = '/'* ]]
then
   SUBJ="\\\$(echo "\\\$SUBJ" | sed 's/ = /=/g;s/, /\//g')"
   SUBJ="/\\\$SUBJ"
fi

case "\\\$TYPE" in
   server|client|ssl)
      sign "\\\${TYPE}Cert" "\\\$CSRFILE" "\\\$SUBJ/description=\\\${TYPE}Cert" "\\\$KEY" "\\\$NEWDATES" "\\\$MD"
      ;;
   signing)
      sign "objectSigningCert" "\\\$CSRFILE" "\\\$SUBJ/description=objectSigningCert" "\\\$KEY" "\\\$NEWDATES" "\\\$MD"
      ;;
   *)
      echo "Enter valid certificate type."
      echo
      Usage
      ;;
esac
EOF_sign
chmod +x sign.sh
}

#----------------------------------------------------------------------------------------------

createGenerateScript () {
cat > generate.sh <<EOF_generate
#!/usr/bin/env bash

# generate.sh version $VER -- creates CSRs and private keys and calls sign.sh to sign CSRs

OPENSSL="\\\$(which openssl)"
KEYLENGTH="$CERTKEYLENGTH"

Usage () {
   echo
   echo "Version $VER"
   echo
   echo "Usage: \\\${0##*/} server|client|ssl|signing" 
   echo "                      \\\"<common-name>[;email=<email-address>];ou=<OU>]]\\\"|\\\"<common-name[|SAN1[|SAN2...]]>\\\" [(now|<start-date>):<end-date>] [$DIGESTS]"
   echo
   echo " This script creates a private key and certificate signing request and signs"
   echo " the request as a cert of the specified type.  It will create PEM, DER, and p12 cert files."
   echo
   echo " Enter the type of certificate desired, where:"
   echo
   echo " server             = keyUsage = critical,digitalSignature,keyEncipherment,keyAgreement; extendedKeyUsage = serverAuth"
   echo " client             = keyUsage = critical,digitalSignature,keyAgreement; extendedKeyUsage = clientAuth"
   echo " ssl                = keyUsage = critical,digitalSignature,keyEncipherment; extendedKeyUsage = clientAuth, serverAuth"
   echo " signing            = keyUsage = critical,digitalSignature"
   echo
   echo " \\\"<common-name>[;email=<email-address>];OU=<OU>]]\\\" You must supply the common name."
   echo "                Optionally, you can add and an email address and/or an OU. Use a"
   echo "                semicolon to separate the common name from the email address and/or the OU."
   echo "                Example:"
   echo "                    \\\"PersonalDevice;email=pilot@airline.com;ou=12345678\\\""
   echo "                In this example, PersonalDevice is the CN." 
   echo " \\\"<common-name[|SAN1[|SAN2...]]>\\\" Optionally, you can add domain variations via SubjectAltNames"
   echo "                (SANs) by adding additional names separated by the '|' character and"
   echo "                wrapping the entire <common-name> expression in double-quotes."
   echo "                For example:"
   echo "                    \\\"proxy.server.example.com|proxy.example.com|ssl.example.com\\\""
   echo "                In this example, proxy.server.example.com will be the cert's CN"
   echo "                and proxy.example.com and ssl.example.com will be SANs."
   echo
   echo " Certificate validity settings (optional):"
   echo " <start-date>:<end-date>    = Desired certificate start validity date in YYMMDDhhmmss"
   echo "                              format, or use 'now' for the current date/time, followed by colon ':'"
   echo "                              then the desired certificate end validity date in YYMMDDhhmmss"
   echo "                              format."
   echo
   echo " $DIGESTS (optional) Override the openssl.cnf default signature algorithm with this value."
   echo
   echo " If no dates are supplied, the start date will be current date and the end date"
   echo " will be $CERTEXP days from now."
   exit 1 
}

# Check for the right number of arguments
if ! (( \\\$# == 2 || \\\$# == 3 || \\\$# == 4 ))
then
   Usage
fi

TYPE="\\\$1"
ORIGINALCN="\\\$2"
DATES=""
MD=""

# Are there optional arguments?
if (( \\\$# >= 3 ))
then
   shift 2
   for i in "\\\$@"
   do
      if [[ \\\$i =~ ^([0-9]{12}|[nN][oO][wW]):[0-9]{12} ]] && [[ -z "\\\$DATES" ]]
      then # ith argument is a date.
         DATES="\\\$i"  
      elif [[ \\\$i =~ ^($DIGESTS)$ ]] && [[ -z "\\\$MD" ]]
      then # ith argument is signature algorithm
         MD="\\\$i"
      else
         echo
         echo "Key file does not exist or date is not in YYMMDDhhmmss:YYMMDDhhmmss or"
         echo "now:YYMMDDhhmmss format or incorrect signature algorithm provided or"
         echo "the same argument type was provided more than once."
         echo
         exit 1
      fi
   done
fi

csr () {

   mkdir -p "\\\$CSRLOC"
   \\\$OPENSSL req -batch -out "\\\${CSRLOC}/\\\${PREFIX}-csr.pem" -newkey rsa:\\\$KEYLENGTH -nodes -keyout "\\\${CSRLOC}/\\\${PREFIX}-key.pem" -config openssl.cnf
   if [ \\\$? -eq 0 ]
   then
      chmod 600 \\\${CSRLOC}/\\\${PREFIX}-key.pem
      echo "\\\${CSRLOC}/\\\${PREFIX}"
   else
      echo ""
   fi
}

cp openssl.cnf openssl.cnf-original

if [[ "\\\$ORIGINALCN" =~ "|" ]]
then
   CN="\\\$(echo \\\$ORIGINALCN | cut -d'|' -f1)"
   OFS="\\\$IFS"
   IFS='|'
   read -a SAN <<< "\\\$ORIGINALCN"
   IFS="\\\$OFS"
   sed "s/^#subjectAltName/subjectAltName/;\
s/^commonName_default=/commonName_default=\\\$CN/" openssl.cnf-original > openssl.cnf
   echo "[ alt_names ]" >> openssl.cnf
   # Remove first element of array because it is the CN, which we already have
   SAN=("\\\${SAN[@]:1}")
   # Look in remainder of array for the SAN values
   for index in "\\\${!SAN[@]}"
   do
      echo "DNS.\\\$((index+1))=\\\${SAN[index]}" >> openssl.cnf
   done
elif [[ "\\\$ORIGINALCN" =~ ";" ]]
then
   OFS="\\\$IFS"
   IFS=';'
   read -a ARRAY <<< "\\\$ORIGINALCN"
   IFS="\\\$OFS"
   CN="\\\${ARRAY[0]}"
   # Remove first element of array because it is the CN, which we already have
   ARRAY=("\\\${ARRAY[@]:1}")
   for J in "\\\${ARRAY[@]}"
   do
      [[ "\\\$J" =~ "email=" ]] && EMAIL="\\\$(echo "\\\$J" | cut -d'=' -f2)"
      [[ "\\\$J" =~ "ou=" ]] && OU3="\\\$(echo "\\\$J" | cut -d'=' -f2)"
   done
   sed "s/^commonName_default=/commonName_default=\\\$CN/;s/^emailAddress_default=/emailAddress_default=\\\$EMAIL/;s/^3.organizationalUnitName_default=/3.organizationalUnitName_default=\\\$OU3/" openssl.cnf-original > openssl.cnf
else
   CN="\\\$ORIGINALCN"
   sed "s/^commonName_default=/commonName_default=\\\$CN/" openssl.cnf-original > openssl.cnf
fi

STAMP=\\\$($DATE "+%Y%m%d%H%M%S")
case "\\\$TYPE" in
   server|client|ssl)
      PROFILE="\\\${TYPE}Cert"
      PREFIX="\\\${STAMP}-\\\${CN}-\\\${PROFILE}"
      CSRLOC="\\\${PROFILE}"
      #FILE="\\\$(csr "\\\$PROFILE" "\\\$SUBJ")"
      FILE="\\\$(csr)"
      [ -s openssl.cnf-original ] && mv -f openssl.cnf-original openssl.cnf
      if [ -f "\\\${FILE}-csr.pem" ]
      then
         echo "Private key: \\\${FILE}-key.pem (there is no password protecting the private key)."
         echo
         ./sign.sh \\\${TYPE} "\\\${FILE}-csr.pem" "\\\${FILE}-key.pem" \\\$DATES \\\$MD
      else
         echo "Could not create CSR."
      fi 
      ;;
   signing)
      PROFILE="objectSigningCert"
      PREFIX="\\\${STAMP}-\\\${CN}-\\\${PROFILE}"
      CSRLOC="\\\${PROFILE}"
      #FILE="\\\$(csr "\\\$PROFILE" "\\\$SUBJ")"
      FILE="\\\$(csr)"
      [ -s openssl.cnf-original ] && mv -f openssl.cnf-original openssl.cnf
      if [ -f "\\\${FILE}-csr.pem" ]
      then
         echo "Private key: \\\${FILE}-key.pem (there is no password protecting the private key)."
         echo
         ./sign.sh \\\${TYPE} "\\\${FILE}-csr.pem" "\\\${FILE}-key.pem" \\\$DATES \\\$MD
      else
         echo "Could not create CSR."
      fi 
      ;;
   *)
      echo "Enter valid certificate type."
      echo
      Usage
esac
EOF_generate
chmod +x generate.sh
}

#-----------------------------------------------------------------------------------------

createRevokeScript () {
cat > revoke.sh <<EOF_revoke
#!/usr/bin/env bash

# revoke.sh version $VER -- Revokes certs and creates a new CRL.

OPENSSL="\\\$(which openssl)"

CAPASSWD="\\\$([ -s $PRIVATE_KEY_PASSPHRASE_FILE ] && cat $PRIVATE_KEY_PASSPHRASE_FILE || echo "")"

Usage () {
   echo
   echo "Version $VER"
   echo
   echo "Usage: \\\${0##*/} (<certificate-file> [<reason>])|D:H [$DIGESTS]" 
   echo
   echo " This script revokes the <certificate-file> signed by the"
   echo " \$1 certificate authority and creates a new CRL where:"
   echo
   echo " <certificate-file> = the name of the file containing the cert to revoke."
   echo "                      Certificate must be base 64 encoded (PEM) format."
   echo 
   echo " <reason> = (optional and case insensitive) one of: unspecified," 
   echo "            keyCompromise, CACompromise, affiliationChanged, superseded,"
   echo "            cessationOfOperation, certificateHold or removeFromCRL."
   echo "            If no reason is supplied, reason 'unspecified' will be used."
   echo
   echo " Alternatively, this script can generate a new CRL with the desired"
   echo " longevity, where:"
   echo
   echo " D is the number of days between 0 and 9999 in which the next CRL is due."
   echo " H is the number of hours between 0 and 99 in which the next CRL is due."
   echo 
   echo " Examples:"
   echo " \\\${0##*/} 0:5"
   echo "    creates a CRL that's valid for 5 hours."
   echo " \\\${0##*/} 10:12"
   echo "    creates a CRL that's valid for 10 days and 12 hours."
   echo " \\\${0##*/} 3:0"
   echo "    creates a CRL that's valid for 3 days."
   echo " \\\${0##*/} 9999:99"
   echo "    creates a CRL that's valid for 9999 days and 99 hours."
   echo
   echo " Optionally, you can specify the CRL's signature algorithm if you"
   echo " want to override the default in openssl.cnf."
   exit 1 
}

copyCrl () {
   echo
   NEXTUPDATE="\\\$(\\\$OPENSSL crl -in crl/\${1}-crl.tmp -noout -nextupdate | cut -d= -f2 | tr -s ' ')"
   CRLNUM="\\\$(\\\$OPENSSL crl -in crl/\${1}-crl.tmp -noout -crlnumber | cut -d= -f2)"
   DEST="crl\\\${CRLNUM}-\${1}-Exp_\\\$(echo "\\\$NEXTUPDATE" | tr ' :' '_')-crl.pem"
   cp -f crl/\${1}-crl.tmp crl/\\\$DEST
   echo "New CRL is in crl/\\\$DEST"
   cp -f crl/\${1}-crl.tmp $COLLECTION/\\\$DEST
   ln -f -s $COLLECTION/\\\$DEST $COLLECTION/\${1}-crl.pem
   echo "and $COLLECTION/\\\$DEST"
   rm -f crl/\${1}-crl.tmp
   echo
   echo "This CRL is valid until \\\${NEXTUPDATE}."
   echo
   echo "NOTE: Symlink $COLLECTION/\${1}-crl.pem now points to this CRL."
   echo
}

# Check for the right number of arguments
if ! (( \\\$# == 1 || \\\$# == 2 || \\\$# == 3 ))
then
   Usage 
fi
   
md=""
REASONS="unspecified|keycompromise|cacompromise|affiliationchanged|superseded|cessationofoperation|certificatehold|removefromcrl"
REASON="-crl_reason unspecified"

if [[ \\\$1 =~ ^[0-9]{1,4}:[0-9]{1,2}$ ]]
then # Looks like D:H
   D=\\\$(echo \\\$1 | cut -d':' -f1)
   H=\\\$(echo \\\$1 | cut -d':' -f2)
   if (( \\\$# == 2 ))
   then # Message Digest signing algorithm supplied
      if [[ \\\$2 =~ ^($DIGESTS)$ ]]
      then
         md="-md \\\$2"
      else
         echo
         echo "ERROR: Invalid signature algorithm."
         echo
         exit 1
      fi
   fi
   echo
   echo -n "Creating new CRL valid for \\\$D days and \\\$H hours..."
   \\\$OPENSSL ca \\\$md -gencrl -keyfile cakey.pem -cert cacert.pem -out crl/\${1}-crl.tmp -config openssl.cnf -crldays \\\$D -crlhours \\\$H -passin pass:"\\\$CAPASSWD" 2>/dev/null
   if [ \\\$? -eq 0 ]
   then
      echo "Done."
      copyCrl
   else
      echo "ERROR: Could not create CRL."
      exit 1
   fi
else # Looks like a file name
   # Does cert file exist?
   if [ ! -f "\\\$1" ]
   then
      echo
      echo "Cert file \\\$1 not found."
      echo
      Usage
   fi
   # Is file a valid cert?
   \\\$OPENSSL x509 -noout -in "\\\$1" 2>/dev/null
   if [ \\\$? -ne 0 ]
   then
      echo
      echo "ERROR: Cert file \\\$1 is invalid.  Must be in PEM format."
      echo
      exit 1
   fi
   # Was cert issued by this CA?
   \\\$OPENSSL verify -CAfile trust-chain.pem "\\\$1"
   if [ ! \\\$? -eq 0 ]
   then
      echo
      echo "ERROR: This CA did not issue the cert in \\\${1}.  Cert not revoked."
      echo
      exit 1
   fi

   # Check for more than one argument

   if (( \\\$# == 2 ))
   then 
      if [[ \\\$2 =~ ^($DIGESTS)$ ]]
      then
         md="-md \\\$2"
      elif [[ \\\${2,,} =~ ^(\\\$REASONS)$ ]]
      then
         REASON="-crl_reason \\\$2"
      else
         echo
         echo "ERROR: Invalid signature algorithm or revocation reason."
         echo
         exit 1
      fi
   fi
   if (( \\\$# == 3 ))
   then
      if [[ \\\${2,,} =~ ^(\\\$REASONS)$ ]]
      then
         REASON="-crl_reason \\\$2"
      else
         echo
         echo "ERROR: Invalid revocation reason.  Valid reasons are:"
         echo "\\\$REASONS" | tr '|' ',' 
         echo
         exit 1
      fi
      if [[ \\\$3 =~ ^($DIGESTS)$ ]]
      then
         md="-md \\\$3"
      else
         echo
         echo "ERROR: Invalid signature algorithm."
         echo
         exit 1
      fi
   fi

   # Revoke cert
   \\\$OPENSSL ca -keyfile cakey.pem -cert cacert.pem -revoke "\\\$1" \\\$REASON -config openssl.cnf -passin pass:"\\\$CAPASSWD"
   if [ \\\$? -eq 0 ]
   then
      # Update CRL
      echo
      echo -n "Creating new CRL..."
      \\\$OPENSSL ca \\\$md -gencrl -keyfile cakey.pem -cert cacert.pem -out crl/\${1}-crl.tmp -config openssl.cnf -passin pass:"\\\$CAPASSWD" 2>/dev/null
      if [ \\\$? -eq 0 ]
      then
         echo "Done."
	      copyCrl
      else
         echo "ERROR: Cert revoked but CRL was not updated.  Unknown error."
         exit 1
      fi
   else
      echo "ERROR: Could not revoke cert in \\\${1}."
      exit 1
   fi
fi
EOF_revoke
chmod +x revoke.sh
}

EOF

}

######################### Begin MAIN section ################################################

# Check for the right number of arguments
if ! (( $# == 3 || $# == 4 ))
then
   Usage 
fi

# Number of tiers within bounds?
if (( $2 < $MINTIERS || $2 > $MAXTIERS ))
then
   Usage
fi

TIERS=$(($2 - 2))

# Signature algorithm valid?
if [[ "$3" =~ ^($DIGESTS)$ ]]
then 
   MD="$3"
else
   echo
   echo "ERROR: The valid signature algorithms are $DIGESTS"
   echo
   Usage
fi

# Optional CA/CRL URI valid?
URLREGEX='(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
if (( $# == 4 ))
then
   if [[ $4 =~ ^($URLREGEX)$ ]]
   then # override default CA CRL URI and drop the trailing / if one exists
      BASEURI="$(echo "$4" | sed 's/\/$//')"
      #echo "URI = $BASEURI"
   else
      echo
      echo "ERROR: \"$4\" is not a valid URI"
      echo
      Usage
   fi
fi

# Make subdirectory for this PKI
BASEDIR="$(pwd)"
PKINAME="$(echo "$1" | tr -cd '[[:alnum:]] ._-')"
DIR="${PKINAME// /}-$(printf "%02g" $2)tier-${MD}"
if [ ! -d "${BASEDIR}/${DIR}" ]
then
   mkdir -p "$BASEDIR/$DIR"
else
   echo
   echo "ERROR: $BASEDIR/$DIR already exists. Choose another ID or delete that directory."
   echo
   exit 1
fi

TOPDIR="$BASEDIR/$DIR"
cd "$BASEDIR/$DIR"
mkdir -p cacerts-and-crls
COLLECTION="$BASEDIR/$DIR/cacerts-and-crls"
#RELATIVEDIR="./$DIR"

DEFAULT_ORG+=" - $PKINAME"

# Make all the common functions...
makeCommon
# ...and load them
. ./makepki-common

# Make Root CA
mkdir -p rootCA
cd rootCA
echo 1000 > serial
touch index.txt
touch index.txt.attr

ROOTEXT="rootCA"
EXT="$ROOTEXT"
DOMAIN="${DIR}.${HOST}"
CN="${EXT}.${DOMAIN}"
EXP="$ROOTEXP"
KEYSIZE="$ROOTKEYLENGTH"
echo | tee "$TOPDIR/README.tmp"
echo "Making PKI for ${DIR}.${HOST} domain in $TOPDIR with" | tee -a "$TOPDIR/README.tmp"
echo "${0##*/} version $VER script using $($OPENSSL version)" | tee -a "$TOPDIR/README.tmp"
echo | tee -a "$TOPDIR/README.tmp"
if [[ $TIERS -ge 0 ]]
then
   echo "This PKI will have $(($TIERS + 2)) tiers including root and issuer." | tee -a "$TOPDIR/README.tmp"
else
   echo "This PKI will have a single tier (the root)." | tee -a "$TOPDIR/README.tmp"
fi 
echo "Certificate requests, certs and CRLs will, by default, use the $(echo $MD | tr '[:lower:]' '[:upper:]') signature algorithm." | tee -a "$TOPDIR/README.tmp"
echo "You can select a different signature algorithm when you generate or sign a certificate with the generate.sh or sign.sh scripts." | tee -a "$TOPDIR/README.tmp"

PATHLEN="$(($TIERS + 3))"
PREVEXT="$EXT"
rootCA_authorityInfoAccess="# authorityInfoAccess = Not Applicable on this CA"
rootCA_crlDistributionPoints="# crlDistributionPoints = Not Applicable on this CA"
interCA_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/${EXT}.${DOMAIN}-cert.pem"
interCA_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/${EXT}.${DOMAIN}-crl.pem"
issuerCA_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/${EXT}.${DOMAIN}-cert.pem"
issuerCA_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/${EXT}.${DOMAIN}-crl.pem"
cert_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/${EXT}.${DOMAIN}-cert.pem"
cert_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/${EXT}.${DOMAIN}-crl.pem"
rootCA_pathlen=",pathlen:$PATHLEN"
createConfig
echo "-------------------------------------------------------------"
getText START "private key passphrase" _CAPASSWD USE_DEFAULT_CAPASSWD "$EXT" HIDE
[[ "x$_CAPASSWD" != "x" ]] && CAPASSWD="$_CAPASSWD"   
getText START "Common Name" _CN USE_DEFAULT_CN "$EXT" SHOW
[[ "x$_CN" != "x" ]] && CN="$_CN" || CN="${EXT}.${DOMAIN}"  
SUBJ="/C=US/ST=WA/O=$DEFAULT_ORG/OU=$DEFAULT_ORGUNIT0/OU=$DEFAULT_ORGUNIT1/OU=$DEFAULT_ORGUNIT2/localityName=Seattle/CN=$CN"
createCA "$EXT" "$KEYSIZE" "$SUBJ/description=$EXT" "$COLLECTION" "$DOMAIN" "$CAPASSWD" "$EXP"
createCrl "${EXT}.${DOMAIN}" "$SUBJ" "$COLLECTION"
# Create sign.sh, the script used to sign CSRs.
createSignScript
# Create generate.sh, the script used to generate and sign certs.
createGenerateScript
# Create revoke.sh, the script used to revoke certs and issue a new CA
createRevokeScript "${EXT}.${DOMAIN}" ""

if [[ $TIERS -lt 0 ]]
then
   # This is a single tier CA (root only)
   ISSUERDIR=$(pwd)
fi


# Make intermediate CA(s) if needed.
INTEREXT="inter"
if [[ $TIERS -gt 0 ]]
then
   for i in $(seq -f "%02g" 1 $TIERS)
   do
      echo "-------------------------------------------------------------"
      PREVEXT="$EXT"
      EXT="${INTEREXT}${i}CA"
      CN="${EXT}.${DOMAIN}"
      EXP="$INTEREXP"
      KEYSIZE="$INTERKEYLENGTH"
      mkdir -p $EXT
      cd $EXT
      rootCA_authorityInfoAccess="# authorityInfoAccess = Not Applicable on this CA"
      rootCA_crlDistributionPoints="# crlDistributionPoints = Not Applicable on this CA"
      interCA_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/${PREVEXT}.${DOMAIN}-cert.pem"
      interCA_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/${PREVEXT}.${DOMAIN}-crl.pem"
      issuerCA_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/${PREVEXT}.${DOMAIN}-cert.pem"
      issuerCA_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/${PREVEXT}.${DOMAIN}-crl.pem"
      cert_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/${EXT}.${DOMAIN}-cert.pem"
      cert_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/${EXT}.${DOMAIN}-crl.pem"
      interCA_pathlen=",pathlen:$(($PATHLEN - $i))"
      createConfig
      if [[ $USE_DEFAULT_CAPASSWD -eq 0 ]]
      then
         getText "" "private key passphrase" _CAPASSWD USE_DEFAULT_CAPASSWD "$EXT" HIDE
         [[ "x$_CAPASSWD" != "x" ]] && CAPASSWD="$_CAPASSWD" || CAPASSWD="$DEFAULT_CAPASSWD"
      fi   
      if [[ $USE_DEFAULT_CN -eq 0 ]]
      then
         getText "" "Common Name" _CN USE_DEFAULT_CN "$EXT" SHOW
         [[ "x$_CN" != "x" ]] && CN="$_CN" || CN="${EXT}.${DOMAIN}" 
      else
         CN="${EXT}.${DOMAIN}"
      fi
      SUBJ="/C=US/ST=WA/O=$DEFAULT_ORG/OU=$DEFAULT_ORGUNIT0/OU=$DEFAULT_ORGUNIT1/OU=$DEFAULT_ORGUNIT2/localityName=Seattle/CN=$CN"
      createCA "$EXT" "$KEYSIZE" "$SUBJ/description=$EXT" "$COLLECTION" "$DOMAIN" "$CAPASSWD" "$EXP"
      createCrl "${EXT}.${DOMAIN}" "$SUBJ" "$COLLECTION"
      # Create sign.sh, the script used to sign CSRs.
      createSignScript
      # Create generate.sh, the script used to generate and sign certs.
      createGenerateScript
      # Create revoke.sh, the script used to revoke certs and issue a new CA
      createRevokeScript "${EXT}.${DOMAIN}" ""
   done
   # If this is the last Intermediate tier (or root tier if a 2 tier PKI), make createMakeIssuingCaScript
   createMakeIssuingCaScript
else
   # If this is the last Intermediate tier (or root tier if a 2 tier PKI), make createMakeIssuingCaScript
   createMakeIssuingCaScript
fi

# Make issuer CA if needed.
if [[ $TIERS -ge 0 ]]
then
   echo "-------------------------------------------------------------"
   PREVEXT="$EXT"
   EXT="issuingCA"
   EXP="$ISSUEREXP"
   KEYSIZE="$ISSUERKEYLENGTH"
   mkdir -p "$EXT"
   cd "$EXT"
   rootCA_authorityInfoAccess="# authorityInfoAccess = Not Applicable on this CA"
   rootCA_crlDistributionPoints="# crlDistributionPoints = Not Applicable on this CA"
   interCA_authorityInfoAccess="# authorityInfoAccess = Not Applicable on this CA"
   interCA_crlDistributionPoints="# crlDistributionPoints = Not Applicable on this CA"
   issuerCA_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/${PREVEXT}.${DOMAIN}-cert.pem"
   issuerCA_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/${PREVEXT}.${DOMAIN}-crl.pem"
   cert_authorityInfoAccess="authorityInfoAccess = caIssuers;URI:${BASEURI}/${EXT}.${DOMAIN}-cert.pem"
   cert_crlDistributionPoints="crlDistributionPoints = URI:${BASEURI}/${EXT}.${DOMAIN}-crl.pem"
   issuerCA_pathlen=",pathlen:2"
   createConfig
   if [[ $USE_DEFAULT_CAPASSWD -eq 0 ]]
   then
      getText "" "private key passphrase" _CAPASSWD USE_DEFAULT_CAPASSWD "$EXT" HIDE
      [[ "x$_CAPASSWD" != "x" ]] && CAPASSWD="$_CAPASSWD" || CAPASSWD="$DEFAULT_CAPASSWD"
   fi   
   if [[ $USE_DEFAULT_CN -eq 0 ]]
   then
      getText "" "Common Name" _CN USE_DEFAULT_CN "$EXT" SHOW
      [[ "x$_CN" != "x" ]] && CN="$_CN" || CN="${EXT}.${DOMAIN}"
   else
      CN="${EXT}.${DOMAIN}"
   fi
   SUBJ="/C=US/ST=WA/O=$DEFAULT_ORG/OU=$DEFAULT_ORGUNIT0/OU=$DEFAULT_ORGUNIT1/OU=$DEFAULT_ORGUNIT2/localityName=Seattle/CN=$CN"
   createCA "$EXT" "$KEYSIZE" "$SUBJ/description=$EXT" "$COLLECTION" "$DOMAIN" "$CAPASSWD" "$EXP"
   createCrl "${EXT}.${DOMAIN}" "$SUBJ" "$COLLECTION"
   # Create sign.sh, the script used to sign CSRs.
   createSignScript
   # Create generate.sh, the script used to generate and sign certs.
   createGenerateScript
   # Create revoke.sh, the script used to revoke certs and issue a new CA
   createRevokeScript "${EXT}.${DOMAIN}" ""
   ISSUERDIR=$(pwd)
fi
echo "-------------------------------------------------------------"

# In the issuingCA directory, remove trust-chain.pem and instead create a symlink 
# named trust-chain.pem pointing to $COLLECTION/${DOMAIN}-cacerts.pem
rm trust-chain.pem && ln -s $COLLECTION/${DOMAIN}-cacerts.pem trust-chain.pem
# Make a symlink in the issuingCA directory to the directory containing all CRLs (and CA certs)
ln -s $COLLECTION crls

# Make a symlink to the original issuingCA directory in ../$COLLECTION
ln -s $ISSUERDIR $TOPDIR/goto-issuingca

echo | tee -a "$TOPDIR/README.tmp"
echo "${DIR}.${HOST} PKI complete." | tee -a "$TOPDIR/README.tmp"

mv "$TOPDIR/README.tmp" "$TOPDIR/README"

#Generate README
cat >> "$TOPDIR/README" << EOF

Each CA cert at all tiers have a private key protected by a passphrase.  The passphrase for  
that CA tier's private key is in a file called '$PRIVATE_KEY_PASSPHRASE_FILE' in each CA tier's directory.

Directory $COLLECTION 
contains all of the CA certificates as separate files as well as 
concatenated into a single file (issuer listed first) called ${DOMAIN}-cacerts.pem.
The CRLs for each CA are also in this directory as separate files.

The CAs in this PKI are organized in a hierarchical directory structure with the rootCA on top.
Each directory corresponds to a CA tier in the PKI and contains a file called trust-chain.pem.
This file contains the CA certs (concatenated) in the trust chain relative to and 
including the current CA tier.  The latest CRL for each tier is also located in the 'crls'
directory that CA tier's directory.

You can manipulate the key lengths for the root, intermediate and issuing CA certificates by 
editing the makepki.sh file.  These variables are near the top.  Change them as needed, but 
remember there is no error checking - use only allowed values: 1024, 2048, 4096, 8129.  

# Key length defaults
ROOTKEYLENGTH=$ROOTKEYLENGTH
INTERKEYLENGTH=$INTERKEYLENGTH
ISSUERKEYLENGTH=$ISSUERKEYLENGTH

You can also change the default values for O, OU0, OU1, and OU2 by changing the variables at the top
of the makepki.sh script.  By default, these values are:
DEFAULT_ORG="$DEFAULT_ORG"
DEFAULT_ORGUNIT0="$DEFAULT_ORGUNIT0"
DEFAULT_ORGUNIT1="$DEFAULT_ORGUNIT1"
DEFAULT_ORGUNIT2="$DEFAULT_ORGUNIT2"

You can create additional issuing CAs at the same tier as the original issuing CA (and optionally 
using the original issuing CA's Subject) using the makeissuingca.sh script.  This script is located
in the folder immediately above the issuingCA folder (which would be the root folder in a 2 tier PKI
or the lowest intermediate tier in a PKI with more than 2 tiers).

The shortcut to the issuing CA directory is ${TOPDIR}/goto-issuingca 
Issue and sign certificates from that directory.  There are scripts in that directory that 
you can use to sign CSRs.  You can also generate certificates and private keys 
for these cert types, as well as revoke certificates.

1) Sign a certificate request to create a certificate

    $ cd ${TOPDIR}/goto-issuingca

   Place the CSR file in this directory. Sign the CSR with this command (set cert validity period
   if desired).

    $ ./sign.sh certificate-type CSR-filename [(now|YYMMDDhhmmss):YYMMDDhhmmss] [$DIGESTS]

2) Generate a certificate request and private key and sign the request to create a certificate 
   (set cert validity period if desired).

    $ cd ${TOPDIR}/goto-issuingca

    $ ./generate.sh certificate-type "common-name[|SAN[|SAN]...]" [(now|YYMMDDhhmmss):YYMMDDhhmmss] [$DIGESTS]
    
3) Revoke a certificate issued by this CA.  This also issues a new CRL.
    
    $ cd ${TOPDIR}/goto-issuingca

    $ ./revoke.sh (certificate-filename [reason])|D:H [$DIGESTS]

   The revoke.sh script is in every CA directory. Use it to revoke
   subordinate CA certificates or generate a CRL with the desired renewal interval.

EOF

echo
echo "See ${TOPDIR}/README for information on using this $DOMAIN PKI."
echo
echo "Go to ${TOPDIR}/goto-issuingca and use sign.sh to sign requests with this CA or use generate.sh"
echo "to create requests and private keys."
echo "generate.sh will automatically call sign.sh to sign the requests it creates.  Use revoke.sh to"
echo "revoke certs issued by this CA."
echo
echo "In the tier (folder) above the issuing CA tier, you can create another issuing CA at the same tier as the"
echo "original issuing CA by using the makeissuingca.sh script."
echo




