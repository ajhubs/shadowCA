#!/usr/bin/env bash
#
# create certificates and sign them with the CA
# that is created with the create_ca.sh script
#
# The variable CRTNAME should be set with the needed/wanted certificate name.
# If needed additional alt_names should be set and the settings might be adjusted.
#

# created files (the private keys above all) are only readable by the owner
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

# CA must be first!
if [ ! -d "${CACERTDIR}" ]; then
	echo "Please create your CA first!"
	exit 1;
fi

while getopts "d:h:i:" opt; do
  case ${opt} in
    h) HNAME+=("${OPTARG}");;
    i) HIP+=("${OPTARG}");;
    d) VALIDDAYS=${OPTARG};;
    s) KEYSECRET=${OPTARG};;
    ?) HELPME=yes;;
    *) HELPME=yes;;
  esac
done

if [ -n "${HELPME}" ]; then
  echo "
  This script will generate certificates, sign them with your ${CANAME} and write them to

  Options available:
      -h  to set Hostnames (can be used multiple times)
      -i  to set IP Adresses (can be used multiple times)
      -d  (optional) Number of Days the certificate is valid (default=365)
  "
  exit 0

fi

if [ -z "${HNAME}" ]; then
  echo "please provide hostname (-h) at least once. Try -? for help.";
  exit 1;
fi

# only plain hostnames, optionally with a leading wildcard (*.example.com)
HNAME_RE='^(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9])?$'
for h in "${HNAME[@]}"; do
  if ! [[ ${h} =~ ${HNAME_RE} ]]; then
    echo "invalid hostname: ${h}";
    exit 1;
  fi
done

# set localhost IP if no other set
if [ -z "${HIP}" ]; then
  HIP+=(127.0.0.1)
fi

# if no VALIDDAYS are set, default 365
if [ -z "${VALIDDAYS}" ]; then
  VALIDDAYS=365
fi


# sort array entries and make them uniq
# read line by line, so a wildcard (*.example.com) is kept as it is
NAMES=(); while IFS= read -r n; do NAMES+=("${n}"); done < <(printf "DNS:%s\n" "${HNAME[@]}" | sort -u)
IPADD=(); while IFS= read -r n; do IPADD+=("${n}"); done < <(printf "IP:%s\n" "${HIP[@]}" | sort -u)

# print each elemet of both arrays with comma seperator
# and create a string from the array content
SUBALT=$(IFS=','; echo "${NAMES[*]},${IPADD[*]}")


######
# WORK STARTS
######

# The first provided Hostname will be used
# as reference as this must be the identifier
# the first name will taken as the name
# (a wildcard is stored as wildcard.example.com)
CRTNAME=${HNAME//\*/wildcard}
WDIR=${CERTDIR}/${CRTNAME}

# abort if cert dir is present
# or create dir
if [ -d "${WDIR}" ];then
	echo -e "Looks like ${HNAME} has already a certificate\n ${WDIR} present \n ABORT now"
	exit 1;
else
	mkdir -p "${WDIR}" || { echo "error creating cert dir"; exit 1;}
	echo "Created ${WDIR} ..."
fi

if [ -z "${WDIR}" ]; then
  echo "WorkDir not set - something went terrible wrong";
  exit 1;
fi

if [ -z "${CRTNAME}" ]; then
  echo "Certificate Name not set - Maybe the first Hostname contains space?";
  exit 1;
fi

# remove the files of this run
# so it can simply be started again
fail() {
  echo -e "\nError: $1 \n" >&2
  rm -f "${WDIR}/${CRTNAME}".{key,cnf,csr,ext,crt,pem}
  rmdir "${WDIR}"
  exit 1;
}

echo "... create private Key for ${CRTNAME}"
# create private key for server
"${SSLBIN}" genrsa -out "${WDIR}/${CRTNAME}.key" "${CRTBIT}" || fail "could not create the private key"


echo "... write configuration for ${CRTNAME} ..."
# The following settings might be adjusted to your needs
# C, ST, L and emailAddress are only added if set in shadowCA.cfg
cat > "${WDIR}/${CRTNAME}.cnf" <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
$( [ -n "${CACOUNTRY}" ] && echo "C = ${CACOUNTRY}" )
$( [ -n "${CASTATE}" ] && echo "ST = ${CASTATE}" )
$( [ -n "${CACITY}" ] && echo "L = ${CACITY}" )
O = ${CANAME}
OU = Support ${CANAME}
CN = ${HNAME}
$( [ -n "${CAMAIL}" ] && echo "emailAddress = ${CAMAIL}" )
EOF


echo "... create Certificate Request for ${CRTNAME} ..."
# create csr
"${SSLBIN}" req -new -config "${WDIR}/${CRTNAME}.cnf" -key "${WDIR}/${CRTNAME}.key" -out "${WDIR}/${CRTNAME}.csr" || fail "could not create the certificate request"


echo "... prepare sign of ${CRTNAME} request ..."
# create .ext file
# alt_names are added here
# extendedKeyUsage is required by macOS/iOS, clientAuth keeps mutual TLS working
cat << EOF > "${WDIR}/${CRTNAME}.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = ${SUBALT}
EOF

echo "... sign of ${CRTNAME} request ..."
# create the certificate
"${SSLBIN}" x509 -req -in "${WDIR}/${CRTNAME}.csr" -CA "${CACERTDIR}"/"${CANAME}".pem -CAkey "${CACERTDIR}"/"${CANAME}".key -CAcreateserial -out "${WDIR}/${CRTNAME}.crt" -days "${VALIDDAYS}" -sha256 -extfile "${WDIR}/${CRTNAME}.ext" || fail "could not sign the certificate (wrong CA pass phrase?)"
# create certificate pem
# that contains certificate and key
cat "${WDIR}/${CRTNAME}.crt" "${WDIR}/${CRTNAME}.key" > "${WDIR}/${CRTNAME}.pem" || fail "could not create ${CRTNAME}.pem"

echo "created ${WDIR}/${CRTNAME} that contains all needed files"
echo ""
ls -la "${WDIR}/"