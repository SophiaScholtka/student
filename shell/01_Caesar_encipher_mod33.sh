#!/bin/sh

java \
-cp ../jCrypt/jCrypt.jar:../00_Caesar/bin \
de.tubs.cs.iti.jcrypt.chiffre.Launcher \
-execute task0.Caesar \
-action encipher \
-key ../00_Caesar/key33.txt \
-cleartext ../text/programmierer.txt \
-ciphertext ../00_Caesar/programmierer_enc.txt
