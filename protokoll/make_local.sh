#!/bin/bash
if [ -z "$KRYPTOUMGEBUNG" ]; then
  echo 
  echo FEHLER: Variable KRYPTOUMGEBUNG nicht gesetzt!
  echo
  echo Setzen Sie die Variable auf den Pfad der Programmierumgebung,
  echo z.B. mit       export KRYPTOUMGEBUNG=~milius
  echo und versuchen Sie es erneut!
else
  cp $KRYPTOUMGEBUNG/protokoll/local/* .
fi
