#!/bin/sh

# Measurement Agent install script
# Outline:
# 1.  load existing environment configuration
# 2.  source the "functions.sh" file:  mtwilson-linux-util-*.sh
# 3.  look for ~/tbootxm.env and source it if it's there
# 4.  force root user installation
# 5.  define application directory layout 
# 6.  backup current configuration and data, if they exist
# 7.  create application directories and set folder permissions
# 8.  store directory layout in env file
# 9.  install prerequisites
# 10. unzip tbootxm archive tbootxm-zip-*.zip into TBOOTXM_HOME, overwrite if any files already exist
# 11. copy utilities script file to application folder
# 12. set additional permissions
# 13. validate correct kernel version
# 14. run additional setup tasks

#####

# default settings
# note the layout setting is used only by this script
# and it is not saved or used by the app script
export TBOOTXM_HOME=${TBOOTXM_HOME:-/opt/tbootxm}
TBOOTXM_LAYOUT=${TBOOTXM_LAYOUT:-home}

# the env directory is not configurable; it is defined as TBOOTXM_HOME/env and
# the administrator may use a symlink if necessary to place it anywhere else
export TBOOTXM_ENV=$TBOOTXM_HOME/env

# load application environment variables if already defined
if [ -d $TBOOTXM_ENV ]; then
  TBOOTXM_ENV_FILES=$(ls -1 $TBOOTXM_ENV/*)
  for env_file in $TBOOTXM_ENV_FILES; do
    . $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
  done
fi

# functions script (mtwilson-linux-util-3.0-SNAPSHOT.sh) is required
# we use the following functions:
# java_detect java_ready_report 
# echo_failure echo_warning
# register_startup_script
UTIL_SCRIPT_FILE=$(ls -1 mtwilson-linux-util-*.sh | head -n 1)
if [ -n "$UTIL_SCRIPT_FILE" ] && [ -f "$UTIL_SCRIPT_FILE" ]; then
  . $UTIL_SCRIPT_FILE
fi

# load installer environment file, if present
if [ -f ~/tbootxm.env ]; then
  echo "Loading environment variables from $(cd ~ && pwd)/tbootxm.env"
  . ~/tbootxm.env
  env_file_exports=$(cat ~/tbootxm.env | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
  if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
else
  echo "No environment file"
fi

# enforce root user installation
if [ "$(whoami)" != "root" ]; then
  echo_failure "Running as $(whoami); must install as root"
  exit -1
fi

export TBOOTXM_LIB=$TBOOTXM_HOME/lib
export TBOOTXM_RPMMIO_MODULES=${TBOOTXM_RPMMIO_MODULES:-$TBOOTXM_LIB/rpmmios}

# note that the env dir is not configurable; it is defined as "env" under home
export TBOOTXM_ENV=$TBOOTXM_HOME/env

# create application directories (chown will be repeated near end of this script, after setup)
for directory in $TBOOTXM_LIB $TBOOTXM_RPMMIO_MODULES; do
  mkdir -p $directory
  chmod 700 $directory
done

# make sure unzip and authbind are installed
TBOOTXM_YUM_PACKAGES="zip unzip"
TBOOTXM_APT_PACKAGES="zip unzip"
TBOOTXM_YAST_PACKAGES="zip unzip"
TBOOTXM_ZYPPER_PACKAGES="zip unzip"
auto_install "Installer requirements" "TBOOTXM"
if [ $? -ne 0 ]; then echo_failure "Failed to install prerequisites through package installer"; exit -1; fi

# extract tbootxm  (tbootxm-zip-0.1-SNAPSHOT.zip)
echo "Extracting application..."
RPMMIO_ZIPFILE=`ls -1 tbootxm-rpmmio-*.zip 2>/dev/null | head -n 1`
unzip -oq $RPMMIO_ZIPFILE -d $TBOOTXM_LIB 

# Get host kernel version
kernelCurrentVersion=$(uname -r)

#Copy appropriate rpmmio.ko for current kernel version
echo "Copying the rpmmio for current kernel version : $kernelCurrentVersion"
echo "$TBOOTXM_RPMMIO_MODULES/rpmmio-${kernelCurrentVersion}.ko"

if [ -n $TBOOTXM_RPMMIO_MODULES ] ; then
  if [ -e "$TBOOTXM_RPMMIO_MODULES/rpmmio-${kernelCurrentVersion}.ko" ] ; then
    RPMMIO_PATH="$TBOOTXM_RPMMIO_MODULES/rpmmio-$kernelCurrentVersion.ko"
  fi
fi

if [ -z $RPMMIO_PATH  ] ; then
  echo_failure "rpmmio module not found for $kernelCurrentVersion"
  exit -1
else
  echo "Copying rpmmio.ko to $TBOOTXM_LIB"
  cp $RPMMIO_PATH $TBOOTXM_LIB/rpmmio.ko
fi

echo_success "RPMMIO modules has been installed successfully."
