#!/bin/bash
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier:
#
# USAGE:
#    ./extend_voucher.sh -s <serial_no> -e <endorsement_cert>
#
# Example of providing serial number and endorsement_cert:
#
#   ./extend_voucher.sh -s abcdef -e "-----BEGIN CERTIFICATE-----\nMIIDUTCCAvegAwIBAgILAJ7LsOWTVU9YRIIwCgYIKoZIzj0EAwIwVTFTMB8GA1UE\nAxMYTnV2b3RvbiBUUE0gUm9vdCBDQSAyMTExMCUGA1UEChMeTnV2b3RvbiBUZWNo\nbm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMjAxMjMwMTMzMzExWhcN\nNDAxMjI2MTMzMzExWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n2ZR2Y9Gz2JhEtdvMW5CBzBP+AwGxC3Nd4gRFzKIRbuMyh94ObkgfTezaep4oUvWy\nFlVGznnxRmiK6Jdkg6Wr4e6LgoVuyCJoAZoOK/uU6t0nOPJ8kmvvmK5/ZA9cnhoc\n1M+BgCFrKwFQafhV6oTBny8bz9q0yhzJw7U8v3Y3ZwYbWFFwY0XAVTEFOqnKTP/Q\nylRaXDc5+/AAwS70KD8va8b70xhWFYWHzMPMbfFSQcFXC9IOM4b1wNxyqjFp2xFs\nMcRF+CdjYhjeOAt4aoLUEK4Ui9sAYjAsdx+kpH65V6sZFD+WvJa1OmjsEcWiwWJo\n0iXS9Un6HG40ybjaO/h9ZQIDAQABo4IBNjCCATIwUAYDVR0RAQH/BEYwRKRCMEAx\nPjAUBgVngQUCARMLaWQ6NEU1NDQzMDAwEAYFZ4EFAgITB05QQ1Q3NXgwFAYFZ4EF\nAgMTC2lkOjAwMDcwMDAyMAwGA1UdEwEB/wQCMAAwEAYDVR0lBAkwBwYFZ4EFCAEw\nHwYDVR0jBBgwFoAUI/TiKtO+N0pEl3KVSqKDrtdSVy4wDgYDVR0PAQH/BAQDAgUg\nMCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCKMGkGCCsGAQUFBwEB\nBF0wWzBZBggrBgEFBQcwAoZNaHR0cHM6Ly93d3cubnV2b3Rvbi5jb20vc2VjdXJp\ndHkvTlRDLVRQTS1FSy1DZXJ0L051dm90b24gVFBNIFJvb3QgQ0EgMjExMS5jZXIw\nCgYIKoZIzj0EAwIDSAAwRQIhALFPf2bHCb8HUbhwyFdQ9BJTdEdALswvZVcDcZy7\nDCIwAiAbOuBqKg2sc+UBmnjxSst2uh6/Ao9SqQkuRQY7nXGlxA==\n-----END CERTIFICATE-----" 
#
# Example of providing all arguments:
#
#   ./extend_voucher.sh -a SECP256R1 -m 127.0.0.1 -s abcdef -u apiUser -k password1 -e "endorsement_cert"
#   ./extend_voucher.sh -a SECP384R1 -m 127.0.0.1 -s abcdef -u apiUser -k password1 -e "endorsement_cert"
#   ./extend_voucher.sh -a RSA2048RESTR -m 127.0.0.1 -s abcdef -u apiUser -k password1 -e "endorsement_cert"

############################################################
# Help                                                     #
############################################################
Help()
{
    # Display Help
    echo "This script is used to extend the voucher with provided serial number"
    echo
    echo "Syntax: ./extend_voucher.sh [-k|h|m|s|u|e]"
    echo "options:"
    echo "k     Manufacturer API password, if not provided defaults to blank."
    echo "m     Manufacturer IP, if not provided defaults to localhost."
    echo "u     API username, if not provided defaults to apiUser"
    echo "s     Serial number to which extension has to performed."
    echo "e     Endorsement cert of the TPM on platform."
    echo "h     Help."
    echo
}

while getopts e:h:k:m:s:u: flag;
do
    case "${flag}" in
        e) ek_cert=${OPTARG};;
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

if [ -z "$ek_cert" ]; then
    echo "Device TPM endorsement cert is mandatory, check usage with -h" >&2
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
printf "%b" "${ek_cert}" >> all_cert.pem
all_cert=`cat all_cert.pem`

get_voucher=$(curl --silent -w "%{http_code}\n" -D - --digest -u ${api_user}:${mfg_api_passwd} --location --request POST "http://${mfg_ip}:${mfg_port}/api/v1/mfg/vouchers/${serial_no}" --header 'Content-Type: text/plain' --data-raw  "$all_cert" -o ${serial_no}_voucher.txt)
get_voucher_code=$(tail -n1 <<< "$get_voucher")
if [ "$get_voucher_code" = "200" ]; then
    echo "Success in downloading extended voucher for device with serial number ${serial_no}"
else
    echo "Failure in getting extended voucher for device with serial number ${serial_no} with response code: ${get_voucher_code}"
fi
