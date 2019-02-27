#!/usr/bin/env bash

pyinstaller --onefile --name="fuzz-sat" --distpath=$(pwd) fuzzer.py
exit

