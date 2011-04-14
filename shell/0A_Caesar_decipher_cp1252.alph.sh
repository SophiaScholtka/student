#!/bin/sh

java \
-cp ../jCrypt/jCrypt.jar:../00_Caesar/bin \
de.tubs.cs.iti.jcrypt.chiffre.Launcher \
-execute task0.Caesar \
-action decipher \
-key ../00_Caesar/key251.txt \
-cleartext ../00_Caesar/programmierer_dec.txt \
-ciphertext ../00_Caesar/programmierer_enc.txt \
-alphabet ../alphabet/cp1252.alph
