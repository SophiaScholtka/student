####### Krypto Makefile

classpath =     `pwd`/../../../../../../:`pwd`/../../../../../../../../chiffre/classes.jar:.:$${JAVA_HOME}/lib/classes.zip
SHELL  =	/bin/sh
JAVAC =		javac -classpath $(classpath)
MAKE =		make

PACKAGE =	'de.tubs.cs.iti.krypto.protokoll'

####### Files

BASEOBJECTS =   ProtocolUtils.class Communicator.class Protocol.class \
		Game.class ServerThread.class Server.class Client.class \
		ClientGUI*.class CmdLineClient.class IClient.class \
		popUpWindow*.class Certificate.class TrustedAuthority.class

OBJECTS = 	$(BASEOBJECTS)

SOURCES =	ProtocolUtils.java Communicator.java Protocol.java \
                Game.java ServerThread.java Server.java Client.java \
		ClientGUI.java CmdLineClient.java IClient.java \
		popUpWindow.java Certificate.java TrustedAuthority.java

####### Implicit rules

.SUFFIXES:
.SUFFIXES: .java .class

.java.class:
	$(JAVAC) $<

####### Explicit rules

all: classes doc

classes: $(OBJECTS)
	-rm -f ../../../../../../.full_list; \
	for X in $(BASEOBJECTS); do \
	  echo "de/tubs/cs/iti/krypto/protokoll/"$$X >> ../../../../../../.full_list ; done
	-rm -f ../../../../../../classes.jar; \
	(cd ../../../../../..; \
	 jar -cf classes.jar `cat .full_list`; \
	 chmod a+r classes.jar; \
	 mv classes.jar ../; \
	 rm -f .full_list)

#	echo ${PACKAGE} | awk -F '.' '{print $$1"/"$$2"/"$$3"/"$$4"/"$$5}' > .pack_dir
# awk: $NF = total number of fields in input record
#	cp -a $(BASEOBJECTS) ../`cat .pack_dir`/
#	cp -a tabellen/ ../`cat .pack_dir`/
#	-rm ../classes.zip
#	(cd ..; zip -r classes.zip `echo ${PACKAGE} | awk -F '.' '{print $$1"/"}'`)

doc:
	-rm -f ../../../../../../../docs/*.html
	javadoc -classpath $(classpath) -d ../../../../../../../docs ${PACKAGE}
	chmod -R a+r ../../../../../../../docs/*

clean:	clean-doc
	-rm -f *.class *.bak *.swp *~ *% #*
	-rm -f ../../../../../../../classes.jar

clean-doc:
	-rm -f ../../../../../../../docs/*.html

