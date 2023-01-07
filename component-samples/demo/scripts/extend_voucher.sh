#!/bin/bash
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier:
#
# Example of providing all arguments:
#
#   ./extend_voucher.sh -a SECP256R1 -m 127.0.0.1 -s abcdef -u apiUser -k password1
#   ./extend_voucher.sh -a SECP384R1 -m 127.0.0.1 -s abcdef -u apiUser -k password1
#   ./extend_voucher.sh -a RSA2048RESTR -m 127.0.0.1 -s abcdef -u apiUser -k password1

############################################################
# Help                                                     #
############################################################
Help()
{
    # Display Help
    echo "This script is used to extend the voucher with provided serial number"
    echo
    echo "Syntax: ./extend_voucher.sh [-k|h|m|s|u]"
    echo "options:"
    echo "k     Manufacturer API password, if not provided defaults to blank."
    echo "m     Manufacturer IP, if not provided defaults to localhost."
    echo "u     API username, if not provided defaults to apiUser"
    echo "s     Serial number to which extension has to performed."
    echo "h     Help."
    echo
}

while getopts h:k:m:s:u: flag;
do
    case "${flag}" in
        h) Help
           exit 0;;
        k) mfg_api_passwd=${OPTARG};;
        m) mfg_ip=${OPTARG};;
        s) serial_no=${OPTARG};;
        u) api_user=${OPTARG};;
        \?) echo "Error: Invalid Option, use -h for help"
            exit 1;;
    esac
done

if [ -z "$serial_no" ]; then
    echo "Serial number of device is mandatory, check usage with -h" >&2
    exit 1
fi

default_attestation_type="SECP256R1"
default_mfg_ip="localhost"
default_api_user="apiUser"
default_mfg_api_passwd=""
mfg_port="8039"

mfg_ip=${mfg_ip:-$default_mfg_ip}
api_user=${api_user:-$default_api_user}
mfg_api_passwd=${mfg_api_passwd:-$default_mfg_api_passwd}

cat owner_cert.txt > all_cert.pem
all_cert=`cat all_cert.pem`

get_voucher=$(curl --silent -w "%{http_code}\n" -D - --digest -u ${api_user}:${mfg_api_passwd} --location --request POST "http://${mfg_ip}:${mfg_port}/api/v1/mfg/vouchers/${serial_no}" --header 'Content-Type: text/plain' --data-raw  "$all_cert" -o ${serial_no}_voucher.txt)
get_voucher_code=$(tail -n1 <<< "$get_voucher")
if [ "$get_voucher_code" = "200" ]; then
    echo "Success in downloading extended voucher for device with serial number ${serial_no}"
else
    echo "Failure in getting extended voucher for device with serial number ${serial_no} with response code: ${get_voucher_code}"
fi
