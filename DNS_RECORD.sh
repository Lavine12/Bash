#!/bin/bash

red='\033[0;31m'
yellow='\033[0;33m'
blue='\033[0;34m'
clear='\033[0m'
green='\033[0;32m'

function header() { echo -e "${blue}${1}${clear}" ; }
function org() { echo -e "${green}${1}${clear}" ; }
function warning() { echo -e "${red}${1}${clear}" ; }

# sends the DNS query to Google’s name server(8.8.8.8) by using the @8.8.8.8 option
function ns_record(){
  NS_RECORD=$(dig +short ns "$varname" @8.8.8.8 | sort)

  header "NS record for $varname : "
   if [ "$NS_RECORD" == "" ]; then
     echo
     warning "No NS record for $varname"
     echo
   else
     echo -e "$NS_RECORD"
     echo
   fi
}

function a_record(){
  A_RECORD=$(dig +short a "$varname" @8.8.8.8 | sort)
  FA_RECORD="$(dig +short a "$varname" @8.8.8.8 | sort | head -n 1)"

  header "A record for $varname : "
   if [ "$A_RECORD" == "" ]; then
     echo
     warning "No A record for $varname"
     echo
   else
     echo -e "$A_RECORD"
     for i in ${A_RECORD}; do
     PTR_RECORD="$(dig +answer -x "$i" @8.8.8.8 | grep "PTR" | sort | head -n-1)"
     if [ "$PTR_RECORD" == "" ]; then
     warning "No PTR record for $i"
     else
     echo "$PTR_RECORD"
     fi
     done
     org "$(curl -s ipinfo.io/"$FA_RECORD" | grep "\"org\":" | xargs | cut -f1 -d ",")"
     echo 
   fi
}

function mx_record(){
  MX_RECORD=$(dig +short MX "$varname" @8.8.8.8 | sort)
  header "MX record for $varname : "
   if [ "$MX_RECORD" == "" ]; then
     echo
     warning "No MX record for $varname"
     echo
   else
     echo -e "$MX_RECORD"
     echo
   fi
}

function mail_record(){
  MAIL_RECORD=$(dig +short a mail."$varname" @8.8.8.8 | sort)

   header "Mail record for $varname : "
   echo -e "$MAIL_RECORD"
   FMAIL_RECORD="$(dig +short a mail."$varname" @8.8.8.8 | sort | head -n 1)"
   if [ "$FMAIL_RECORD" == "" ]; then
     warning "No Mail record for $varname"
     echo
   else
     org "$(curl -s ipinfo.io/"$FMAIL_RECORD" | grep "\"org\":" | xargs | cut -f1 -d ",")"
     echo
   fi
}

function webmail_record(){
  WEBMAIL_RECORD=$(dig +short a webmail."$varname" @8.8.8.8 | sort)

  header "Webmail record for $varname : "
   echo -e "$WEBMAIL_RECORD"
   FWEBMAIL_RECORD="$(dig +short a webmail."$varname" @8.8.8.8 | sort | head -n 1)"
   if [ "$WEBMAIL_RECORD" == "" ]; then
     warning "No Webmail record for $varname"
     echo
   else
     org "$(curl -s ipinfo.io/"$FWEBMAIL_RECORD" | grep "\"org\":" | xargs | cut -f1 -d ",")"
     echo
   fi
}

function txt_record(){
  TXT_RECORD=$(dig +short txt "$varname" @8.8.8.8 | sort)

  header "TXT record for $varname : "
   if [ "$TXT_RECORD" == "" ]; then
     echo
     warning "No TXT record for $varname"
   else
     echo -e "$TXT_RECORD"
   fi
   echo
}

function get_record () {
   ns_record
   a_record
   mx_record
   mail_record
   webmail_record
   txt_record
}

function check_and_pass () {
   if [[ $varname =~ \.(com|net|org|info|name|biz|asia|name.my|biz.my|com.my|net.my|org.my|gov.my|edu.my|mil.my|my|cc|me|tv|fm)$ ]]
then
   get_record
elif [ "$varname" == 'pass' ]
then
   password=$(openssl rand -base64 12)
   echo -e "${yellow}$password ${clear}"
else
   warning "Please check your input"
   echo
   (( x++ )) || true
   if [ $x -eq 4 ]; then
       warning "Last attempt !"
       echo
   else
       return
   fi
fi
}

#script start from here
function userinput () {
  x=1
  while [ $x -ne 5 ]
  do
    read -r -p "Input : " varname
    echo
    check_and_pass
  done
}

#main
userinput
