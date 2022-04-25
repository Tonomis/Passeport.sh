#!/bin/bash

#### TO do ####
#REPLY menu
#Ajout réseau
#Aérer le code
#Vérifier heure locale (NTP)
#Check config sshd (root allowed, )
#Vérifier up carte réseau
#Vérifier ping + vérifier dns
#IP publique
#

# Usage: bannerColor "my title" "red" "*"
function bannerColor() {
    case ${2} in
    black) color=0 ;;
    red) color=1 ;;
    green) color=2 ;;
    yellow) color=3 ;;
    blue) color=4 ;;
    magenta) color=5 ;;
    cyan) color=6 ;;
    white) color=7 ;;
    *) color=0 ;;
    esac
    local msg="${3} ${1} ${3}"
    local edge=$(echo "${msg}" | sed "s/./${3}/g")
    tput setaf ${color}
    #tput bold
    echo "${edge}"
    echo "${msg}"
    echo "${edge}"
    tput sgr 0
    echo
}

default() {
    bannerColor "         PASSEPORT         " "blue" "-"
    hostname=$(echo "Hostname : " && hostname)
    ip=$(echo "IP : " && hostname -I)
    defaultRoute=$(echo "| Route par défault : " && ip route show | grep default | cut -d " " -f 3-)
    distrib=$(echo "OS : " && cat /etc/os-* | grep PRETTY_NAME | cut -d '"' -f2) 
    version=$(echo -n "| version : " && cat /etc/*_version)
    cpu=$(echo -n "CPU : " && lscpu | grep "Model name" | cut -d ":" -f 2 | tr -s " ")
    kernel=$(echo -n "Kernel : " && uname -v)
    ram=$(echo -n "RAM Total : " &&  grep MemTotal /proc/meminfo | tr -s " " | cut -d ":" -f 2 )
    nbSecurityUpdate=$(apt list --upgradable 2>/dev/null | grep "\-security" | wc -l)
    securityUpdate=$(echo -n "Nombre de version de sécurité à appliquer : " && apt list --upgradable 2>/dev/null | grep "\-security" | wc -l)
    uptime=$(echo "Uptime : " && uptime --pretty)
    echo $hostname
    echo $distrib $version 
    echo $kernel
    echo $cpu
    echo $ram
    if [ "$nbSecurityUpdate" -gt "1" ] ; then tput setaf 1 ; fi
    echo $securityUpdate
    tput sgr 0
    echo -e "\n"
    bannerColor " disques " "green" "-"
    df -h | grep -v tmpfs | grep -v udev
    df -ih | grep -v tmpfs | grep -v udev
    echo -e "\n"
    bannerColor " réseau " "yellow" "-"
    echo $ip $defaultRoute
    echo -e "\n"
}

hardware() {
    bannerColor "Hardware" "blue" "*"
    echo "Composants de l'ordinateur"
    lspci
    echo -e "\n"
    lscpu
    echo -e "\n"
}

disc() {
    bannerColor "Disc" "green" "-"

}

user() {
    bannerColor "Users" "cyan" "-"
    userbash=$(grep -v /sbin/nologin /etc/passwd | grep -v /bin/false | cut -d ":" -f 1)
    userlogged=$(echo "Utilisateurs connectés :")
    sudoUsers=$(grep sudo /etc/group | cut -d ":" -f 4 | sed 's/,/ /g')
    userHome=$(grep home /etc/passwd | cut -d ":" -f 1)
    function userDuHome { for i in $userHome; do sudo du -h -d0 /home/$i ; done }
    echo $userlogged  && who | sort
    echo -e "\n"
    echo "Utilisateurs ayant accès au terminal : " && echo $userbash
    echo -e "\n"
    echo "Utilisateurs ayant l'accès sudo: " && echo $sudoUsers
    echo -e "\n"
    echo "Occupation mémoire des /home respectifs :"
    userDuHome
    echo -e "\n"

}

menu ()
{
    PS3="Select a menu : "
    select choice in Default Hardware Disc User Exit
    do 
    case $choice in 
        Hardware) hardware ;;
        Disc) disc ;;
        User) user ;;
        Exit) echo "Bye !" && break ;;
        *) default ;;
        esac 
    done
}

### MAIN ###

menu 

