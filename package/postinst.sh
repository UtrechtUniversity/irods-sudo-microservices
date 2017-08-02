#!/bin/sh

# CPack-generated package overwrites ownership of /etc/irods.
# Restore /etc/irods ownership to irods:irods.
# This is the original ownership setting in iRODS 4.2.1.
chown irods:irods /etc/irods /etc/irods/sudo-default-policies.re
