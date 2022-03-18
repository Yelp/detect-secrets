#!/bin/sh
##
#  This script gets packaged with a Redhat python UBI (Universal Base Image) and serves as the entrypoint of the container.
#  The IBM Detect Secrets CLI tool is also packaged in the container; these scripts will run:
#      1) detect-secrets scan --update
#      2) followed by:  detect-secrets audit --report with fail-on options
#  to generate a report and emit an exit code (1 = fail, 0 = pass) on selected conditions based on the specified fail-on flags.
#
#  Note:  We include a SKIP_SCAN flag if one desired to skip the scan --update part (step 1 above) and just to the audit -report with existing baseline
#         This option might be chosen in the case that the user has already updated their baseline file locally
#
#  This script takes the following parameters via Environment Variables:
#    BASELINE :  This is the filename to use to store/read the scan baseline output/input.
#      * Default:  .secrets.baseline
#
#    SKIP_SCAN : (True/False) Allows for the skipping of the Scan --update part that updates the baseline file.
#      * Default:  False
#
#    JSON : (True/False) Whether to output result in JSON format vs the Table format
#      * Default:  False
#        Note:  Setting True is mutually exclusive with setting OMIT_INSTRUCTIONS=True.
#
#    OMIT_INSTRUCTIONS : (True/False) Whether to output resolution instructions for failed conditions.
#      * Default:  False
#        Note:  Setting True is mutually exclusive with setting JSON=True.
#
#    FAIL_ON_LIVE : (True/False) Sets the condition to fail audit if there are verified live secrets found
#      * Default:  True
#
#    FAIL_ON_UNAUDITED : (True/False) Sets the condition to fail audit if there are unaudited potential secrets found
#      * Default:  True
#
#    FAIL_ON_AUDITED_REAL : (True/False) Sets the condition to fail audit if there are audited and set to real secrets found
#      * Default:  True
#
# Example manual docker run within packaged container (git-defenders/detect-secrets-redhat-ubi):
#    docker run  --env BASELINE=.secrets.baseline  --env FAIL_ON_LIVE=False  -it -a stdout --rm -v $(pwd):/code git-defenders/detect-secrets-redhat-ubi
##

## Constants for FAIL_ON_xx Environment Varibles
_false="false"
_true="true"

## Setting Baseline filename, skip_scan, and fail-on-xx Boolean Defaults
_baseline_default=.secrets.baseline
_skip_scan_default=$_false
_json_default=$_false
_omit_instructions_default=$_false
_fail_live_default=$_true
_fail_unaudited_default=$_true
_fail_audited_real_default=$_true

## Constants representing Detect Secrets audit -reports --fail-on-xx paramenter options
_fail_live_option="--fail-on-live"
_fail_unaudited_option="--fail-on-unaudited"
_fail_audited_real_option="--fail-on-audited-real"
_omit_instructions_option="--omit-instructions"
_json_option="--json"

## Reading input Environment Variables while setting defaults for missing Environment Variables
baseline=${BASELINE:=$_baseline_default}
json=${JSON:=${_json_default}}
omit_instructions=${OMIT_INSTRUCTIONS:=$_omit_instructions_default}
skip_scan=${SKIP_SCAN:=$_skip_scan_default}
fail_live=${FAIL_ON_LIVE:=$_fail_live_default}
fail_unaudited=${FAIL_ON_UNAUDITED:=$_fail_unaudited_default}
fail_audited_real=${FAIL_ON_AUDITED_REAL:=$_fail_audited_real_default}

##
# Declare normalize function for normalizing the user input for Boolean vales to either true or false
#   - This function allows the user input to be case-insensitive (ie TRUE, true, True, TrUe are all = true)
#   - This function will return the default value for input if input represents any value other than true or false
#     Note:  defaulting for missing Env Var input is handled before this function gets called
#
#   Inputs:
#     - raw user input value for skip_scan or fail-on-xx parameter
#     - default value for that same parameter
#   Output:
#     - case-insentive value (true/false) or default value
##
function normalize {
    local user_param=$1
    local default_val=$2

    if [[ "${user_param,,}" == "$_true" ]]  # Note:  ${var,,} means to lowercase of var
    then
        result="$_true"
    elif [[ "${user_param,,}" == "$_false" ]]
    then
        result="$_false"
    else
        result="$default_val"
    fi

    echo $result
}

## Initialize Detect Secrets audit_report parameter string
audit_report_params=' '

##
# Starting the pipeline Detect Secrets run
##
echo "[ Starting Detect Secrets run ]"
echo
echo "...using baseline: $baseline"

##
# Checking Env Vars and appending coresponding Detect Secrets audit report parameters to the parameter string
# Note:  Env Var input values are normalized before being checked. Thus case-insensitive and/or defaulted if necessary
#        Thus the values will always be either true or false after they are normalized
##

# skip_scan parameter
skip_scan="$(normalize $skip_scan $_skip_scan_default)"
if [[ "$skip_scan" == "$_true" ]]
then
  echo "...skip scan with baseline update: $_true"
else
  echo "...skip scan with baseline update: $_false"
fi

# json parameter
json="$(normalize $json $_json_default)"
if [[ "$json" == "$_true" ]]
then
  echo "...output json: $_true"
  audit_report_params="$audit_report_params $_json_option"
else
  echo "...output json: $_false"
fi

# omit_instructions parameter
omit_instructions="$(normalize $omit_instructions $_omit_instructions_default)"
if [[ "$omit_instructions" == "$_true" ]]
then
  echo "...omit instructions: $_true"
  audit_report_params="$audit_report_params $_omit_instructions_option"
else
  echo "...omit instructions: $_false"
fi


# Fail On Live
fail_live="$(normalize $fail_live $_fail_live_default)"
if [[ "$fail_live" == "$_true" ]]
then
  echo "...fail on live: $_true"
  audit_report_params="$audit_report_params $_fail_live_option"
else
  echo "...fail on live: $_false"
fi

# Fail On Unaudited
fail_unaudited="$(normalize $fail_unaudited $_fail_unaudited_default)"
if [[ "$fail_unaudited" == "$_true" ]]
then
  echo "...fail on unaudited: $_true"
  audit_report_params="$audit_report_params $_fail_unaudited_option"
else
  echo "...fail on unaudited: $_false"
fi
# Fail On Audited Real
fail_audited_real="$(normalize $fail_audited_real $_fail_audited_real_default)"
if [[ "$fail_audited_real" == "$_true" ]]
then
  echo "...fail on audited real: $_true"
  audit_report_params="$audit_report_params $_fail_audited_real_option"
else
  echo "...fail on audited real: $_false"
fi

## Calling Detect Secrets scan with baseline update to create or update existing baseline file
if [[ "$skip_scan" == "$_false" ]]
then
  echo
  echo "Scanning code directory (docker volume mounted to $PWD) and updating baseline file $baseline ... "
  detect-secrets scan --update $baseline
fi

echo

## Calling Detect Secrets audit --report against baseline with user specified fail-on options
echo "Running report: Baseline $baseline - Options:$audit_report_params"
echo
detect-secrets audit --report $audit_report_params $baseline
# Save detect-secrets return code
exit_code=$?

echo

## Ending the pipeline Detect Secrets run
if [[ $exit_code == 0 ]]
then
    echo "[ Ending Detect Secrets - run succeeded ]"
else
    echo "[ Ending Detect Secrets - run failed ]"
fi

# Exit, emitting the detect-secrets return code
exit $exit_code
