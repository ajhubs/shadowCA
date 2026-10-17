#!/usr/bin/env bash
#
#  Ressources from the web
#
#  https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/
#
#  In addition the shadowCA.pem should be added to your browser if you want to use the created certifcates
#  for Web services
#########

# created files (the CA key above all) are only readable by the owner
umask 077

WPATH=$( pwd )
# Check if we find the configuration in the current path
[ -f "${WPATH}"/shadowCA.cfg ]  && CFGPATH="${WPATH}"

# Subtitute bin$ dir from present pwd 
# after that retry to find configuration
WPATH=$( echo "${WPATH}" | sed -e 's#/bin$##g' )
[ -f "${WPATH}"/shadowCA.cfg ] && CFGPATH="${WPATH}"

# if no config is found 
# we have no base dir and exit 
[ -d "${CFGPATH}" ] || { echo "shadowCA.cfg not found, run this from the shadowCA folder or its bin folder" >&2; exit 1; }

# remove unwanted from cfg file
# that might harm and is not wanted
configfile="${CFGPATH}/shadowCA.cfg"
configfile_secured="${CFGPATH}/.shadowCA.cfg"

# check if the file contains something we don't want
if egrep -q -v '^#|^[^ ]*=[^;]*' "$configfile"; then
  echo "Config file is unclean, cleaning it..." >&2
  # filter the original to a new file
  egrep '^#|^[^ ]*=[^;&]*'  "$configfile" > "$configfile_secured"
  configfile="$configfile_secured"
fi

# now source it, either the original or the filtered variant
source "$configfile"

if [ -z "${SSLBIN}" ]; then
  echo "no openssl detected aborting"
  exit 1;
fi

# Check if CA Key or Certificate is already present
if [ -f "${CACERTDIR}/${CANAME}.key" ] || [ -f "${CACERTDIR}/${CANAME}.pem" ]; then
  echo -e "Error \n shadowCA Key or Certificate already present \n Will stop creating a new CA"
  exit 1;
fi

# remove what this run created
# so it can simply be started again
fail() {
  echo -e "\nError: $1 \n" >&2
  rm -f "${CACERTDIR}/${CANAME}".{cnf,key,pem,der}
  exit 1;
}

# create CA Folder if not present
[ -d "${CACERTDIR}" ] || mkdir -p "${CACERTDIR}"

# write the configuration for your CA
# that will be used to create
# In addition later it is possible to check
# what settings are used.
# C, ST, L and emailAddress are only added if set in shadowCA.cfg
cat > "${CACERTDIR}"/"${CANAME}".cnf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
$( [ -n "${CACOUNTRY}" ] && echo "C = ${CACOUNTRY}" )
$( [ -n "${CASTATE}" ] && echo "ST = ${CASTATE}" )
$( [ -n "${CACITY}" ] && echo "L = ${CACITY}" )
O = ${CANAME}
OU = Support ${CANAME}
CN = ${CANAME}
$( [ -n "${CAMAIL}" ] && echo "emailAddress = ${CAMAIL}" )
EOF


# generate private key
echo -e "\nGenerate Private Key ... \n choose a strong CA Password if requested!! \n"
"${SSLBIN}" genrsa -des3 -out "${CACERTDIR}"/"${CANAME}".key 2048 || fail "could not create the CA key (pass phrases did not match?)"

# generate root certificate
# keyUsage is needed for strict verification (e.g. Python 3.13+)
echo -e  "\nSign ROOT Certificate with your previous entered CA Password ... \n "
"${SSLBIN}" req -addext basicConstraints=critical,CA:TRUE,pathlen:1 -addext keyUsage=critical,keyCertSign,cRLSign -x509 -new -nodes -key "${CACERTDIR}"/"${CANAME}".key -sha256 -days "${CAVDAYS}" -config "${CACERTDIR}"/"${CANAME}".cnf -out "${CACERTDIR}"/"${CANAME}".pem || fail "could not create the CA certificate (wrong pass phrase?)"

# create DER from ca.pem
echo -e "\nCreate DER from ${CACERTDIR}/${CANAME}.pem "
"${SSLBIN}" x509 -in "${CACERTDIR}"/"${CANAME}".pem -inform pem -out "${CACERTDIR}"/"${CANAME}".der -outform der || fail "could not create the DER copy of the CA certificate"

echo "Success"
echo -e "now you can Import\n ${CACERTDIR}/${CANAME}.pem or\n ${CACERTDIR}/${CANAME}.der\ninto your Systems Truststore\n"
echo "This is needed on all System that should trust this CA."
