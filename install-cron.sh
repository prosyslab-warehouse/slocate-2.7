#!/bin/bash

CRONTAB=/etc/crontab

if [ ! -e $CRONTAB ] ; then
   echo "Could not locate $CRONTAB file"
   exit 0
fi

grep "slocate\|updatedb" $CRONTAB >/dev/null 2>&1

if [ "$?" -eq "1" ] ; then

   # Check if updatedb exists
   if [ -x /usr/bin/updatedb ] ; then
   
      # Check if a configuration file exists
      if [ -f /etc/updatedb.conf ] ; then
	 echo "0 6    * * *   root /usr/bin/updatedb" >>$CRONTAB
      else
         echo "0 6    * * *   root /usr/bin/updatedb -f proc" >>$CRONTAB
      fi      
   elif [ -x /usr/bin/slocate ] ; then
       echo "0 6    * * *   root /usr/bin/slocate -u -f proc" >>$CRONTAB
   else
       echo "Could not find a slocate binary"
   fi
   
else
   echo "Cron entry already exists in $CRONTAB for slocate"
fi
