#!/bin/sh
cd /usr/src
mkdir sys.2.2.8-RELEASE
cd sys.2.2.8-RELEASE
(cd ../sys ; tar cf - . ) | tar xvfp -
