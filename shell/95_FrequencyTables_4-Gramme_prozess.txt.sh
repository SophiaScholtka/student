#!/bin/sh

java \
-cp ../jCrypt/jCrypt.jar \
de.tubs.cs.iti.jcrypt.chiffre.FrequencyTables \
../alphabet/prozess.alph \
../text/prozess.txt \
4 \
100
