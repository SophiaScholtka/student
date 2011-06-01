#!/bin/sh
if [ -z $KRYPTOUMGEBUNG ]; then
  echo Warnung: Variable KRYPTOUMGEBUNG nicht gesetzt! 
  echo Starte trotzdem.
  java de.tubs.cs.iti.krypto.protokoll.Server $*
else
  java -classpath "$KRYPTOUMGEBUNG/chiffre/classes.jar:$KRYPTOUMGEBUNG/protokoll/classes.jar:." de.tubs.cs.iti.krypto.protokoll.Server $*
fi