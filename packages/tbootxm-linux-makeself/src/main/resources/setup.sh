#!/bin/sh

# Measurement Agent install script
# Outline:
# 1. source the "functions.sh" file:  mtwilson-linux-util-3.0-SNAPSHOT.sh
# 2. load existing environment configuration
# 3. look for ~/tbootxm.env and source it if it's there
# 4. prompt for installation variables if they are not provided
# 5. determine if we are installing as root or non-root user; set paths
# 6. detect java
# 7. if java not installed, and we have it bundled, install it
# 8. unzip tbootxm archive tbootxm-zip-0.1-SNAPSHOT.zip into /opt/tbootxm, overwrite if any files already exist
# 9. link /usr/local/bin/tbootxm -> /opt/tbootxm/bin/tbootxm, if not already there
# 10. add tbootxm to startup services
# 11. look for TBOOTXM_PASSWORD environment variable; if not present print help message and exit:
#     Measurement Agent requires a master password
#     to generate a password run "export TBOOTXM_PASSWORD=$(tbootxm generate-password) && echo TBOOTXM_PASSWORD=$TBOOTXM_PASSWORD"
#     you must store this password in a safe place
#     losing the master password will result in data loss
# 12. tbootxm setup
# 13. tbootxm start

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

# define application directory layout
if [ "$TBOOTXM_LAYOUT" == "linux" ]; then
  export TBOOTXM_CONFIGURATION=${TBOOTXM_CONFIGURATION:-/etc/tbootxm}
  export TBOOTXM_REPOSITORY=${TBOOTXM_REPOSITORY:-/var/opt/tbootxm}
  export TBOOTXM_LOGS=${TBOOTXM_LOGS:-/var/log/tbootxm}
elif [ "$TBOOTXM_LAYOUT" == "home" ]; then
  export TBOOTXM_CONFIGURATION=${TBOOTXM_CONFIGURATION:-$TBOOTXM_HOME/configuration}
  export TBOOTXM_REPOSITORY=${TBOOTXM_REPOSITORY:-$TBOOTXM_HOME/repository}
  export TBOOTXM_LOGS=${TBOOTXM_LOGS:-$TBOOTXM_HOME/logs}
fi
export TBOOTXM_BIN=$TBOOTXM_HOME/bin
export TBOOTXM_JAVA=$TBOOTXM_HOME/java

# note that the env dir is not configurable; it is defined as "env" under home
export TBOOTXM_ENV=$TBOOTXM_HOME/env

tbootxm_backup_configuration() {
  if [ -n "$TBOOTXM_CONFIGURATION" ] && [ -d "$TBOOTXM_CONFIGURATION" ]; then
    datestr=`date +%Y%m%d.%H%M`
    backupdir=/var/backup/tbootxm.configuration.$datestr
    cp -r $TBOOTXM_CONFIGURATION $backupdir
  fi
}

tbootxm_backup_repository() {
  if [ -n "$TBOOTXM_REPOSITORY" ] && [ -d "$TBOOTXM_REPOSITORY" ]; then
    datestr=`date +%Y%m%d.%H%M`
    backupdir=/var/backup/tbootxm.repository.$datestr
    cp -r $TBOOTXM_REPOSITORY $backupdir
  fi
}

# backup current configuration and data, if they exist
tbootxm_backup_configuration
tbootxm_backup_repository

if [ -d $TBOOTXM_CONFIGURATION ]; then
  backup_conf_dir=$TBOOTXM_REPOSITORY/backup/configuration.$(date +"%Y%m%d.%H%M")
  mkdir -p $backup_conf_dir
  cp -R $TBOOTXM_CONFIGURATION/* $backup_conf_dir
fi

# create application directories (chown will be repeated near end of this script, after setup)
for directory in $TBOOTXM_HOME $TBOOTXM_CONFIGURATION $TBOOTXM_ENV $TBOOTXM_REPOSITORY $TBOOTXM_LOGS; do
  mkdir -p $directory
  chmod 700 $directory
done

# store directory layout in env file
echo "# $(date)" > $TBOOTXM_ENV/tbootxm-layout
echo "export TBOOTXM_HOME=$TBOOTXM_HOME" >> $TBOOTXM_ENV/tbootxm-layout
echo "export TBOOTXM_CONFIGURATION=$TBOOTXM_CONFIGURATION" >> $TBOOTXM_ENV/tbootxm-layout
echo "export TBOOTXM_REPOSITORY=$TBOOTXM_REPOSITORY" >> $TBOOTXM_ENV/tbootxm-layout
echo "export TBOOTXM_JAVA=$TBOOTXM_JAVA" >> $TBOOTXM_ENV/tbootxm-layout
echo "export TBOOTXM_BIN=$TBOOTXM_BIN" >> $TBOOTXM_ENV/tbootxm-layout
echo "export TBOOTXM_LOGS=$TBOOTXM_LOGS" >> $TBOOTXM_ENV/tbootxm-layout

# make sure unzip and authbind are installed
TBOOTXM_YUM_PACKAGES="zip unzip make libgcc gcc-c++ libxml2-devel openssl-devel kernel-devel dos2unix"
TBOOTXM_APT_PACKAGES="zip unzip make gcc g++ libxml2-dev libssl-dev linux-kernel-headers dos2unix"
TBOOTXM_YAST_PACKAGES="zip unzip"
TBOOTXM_ZYPPER_PACKAGES="zip unzip make gcc gcc-c++ libxml2-devel libopenssl-devel kernel-desktop-devel dos2unix"
auto_install "Installer requirements" "TBOOTXM"
if [ $? -ne 0 ]; then echo_failure "Failed to install prerequisites through package installer"; exit -1; fi

# delete existing java files, to prevent a situation where the installer copies
# a newer file but the older file is also there
if [ -d $TBOOTXM_HOME/java ]; then
  rm $TBOOTXM_HOME/java/*.jar
fi

# extract tbootxm  (tbootxm-zip-0.1-SNAPSHOT.zip)
echo "Extracting application..."
TBOOTXM_ZIPFILE=`ls -1 tbootxm-*.zip 2>/dev/null | head -n 1`
unzip -oq $TBOOTXM_ZIPFILE -d $TBOOTXM_HOME

# copy utilities script file to application folder
cp $UTIL_SCRIPT_FILE $TBOOTXM_HOME/bin/functions.sh

# set permissions
chmod 700 $TBOOTXM_HOME/bin/*

echo_success "Installation complete"
