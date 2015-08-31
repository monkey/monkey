#!/bin/sh

rm -rf build/*
fakeroot debian/rules clean
fakeroot debian/rules build
fakeroot debian/rules binary
