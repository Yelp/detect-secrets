# Description:
#   Windows Powershell wrapper for detect-secret.
#   Once installed, allow Windows user to use "detect-secrets" command in Powershell env.
#   This script relies on detect-secrets docker image.
#
# Installation:
#   1. Create a folder under $HOME\Documents\WindowsPowerShell\Modules\ named "detect-secrets"
#   2. Put this script under $HOME\Documents\WindowsPowerShell\Modules\detect-secrets\
#   3. In any Powershell window, start using "detect-secrets"! :-)
#
# Note:
#   This Powershell module will create a command called "detect-secrets". If you have already installed
#   the detect-secrets pip module, you should remove it to avoid command conflict.
function detect-secrets {
    $current_dir = (Get-Location).Path
    $dss_image_tag = "dss-latest"
    $dss_image = "icr.io/git-defenders/detect-secrets:${dss_image_tag}"

    docker run --rm -it -v ${current_dir}:/code ${dss_image} $args
}
