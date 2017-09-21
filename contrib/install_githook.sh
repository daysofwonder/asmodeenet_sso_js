#!/usr/bin/env bash

if [ -d .git/hooks ]; then
	cp contrib/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
fi
