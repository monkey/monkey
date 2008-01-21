#!/bin/sh

# This script file delete every object or Makefile file located in
# modules.

DELETE="rm -rf"
OBJECTS=`find | grep \\\.o`
MAKEFILES=`find | grep Makefile`

$DELETE $OBJECTS $MAKEFILES
