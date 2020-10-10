#!/bin/sh
ME=`whoami`
HERE=`pwd`
LOF="$HERE/ListOfCerts.txt"
rm -f $LOF
if test ! -d certs ; then
   mkdir certs
fi

SSLDIR=`openssl version -d | awk '{ printf $2 }' | sed 's/"//g'`
CERTDIR="$SSLDIR/certs"
cd $CERTDIR
ls -1 *pem > $LOF

while read LINE ; do
  echo $LINE
  HASH=`openssl x509 -subject_hash -in $CERTDIR/$LINE -noout`
  cp $CERTDIR/$LINE $HERE/certs/$HASH.0; chmod 600 $HERE/certs/$HASH.0
  cp $CERTDIR/$LINE $HERE/certs ; chmod 600 $HERE/certs/$LINE
done < $LOF
rm -f $LOF
