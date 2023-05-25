.PHONY: all addlicense install_binaries install clean db

ROOT_DIR       := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

SHELL          := /bin/bash

BINARY         := dmng

LICENSE_TYPE   := "mit"
LICENSE_HOLDER := "Unibg Seclab (https://seclab.unibg.it)"

addlicense:
	go get -u github.com/google/addlicense
	$(shell go env GOPATH)/bin/addlicense -c $(LICENSE_HOLDER) -l $(LICENSE_TYPE) .

all: install

# install dependencies
install_binaries:
ifneq ($(shell id -u), 0)
	@ echo "Please run this target as root to install 'sqlite3'"
else
	@ echo "Installing sqlite3..."
	@ apt install sqlite3 -y
endif

# build the tool locally
_build:
	@ go build .

# install the tool system wide
install: _build
	@ mkdir -p ~/.config/dmng
	@ sudo mv dmng /usr/bin/$(BINARY)
	@ sudo chmod 701 /usr/bin/$(BINARY)
	@ cp -f utils/usage.txt ~/.config/dmng/usage.txt

# uninstall the tool from the system
clean:
	@ sudo rm -f /usr/bin/$(BINARY)
	@ rm -rf ~/.config/dmng
	@ rm -rf ~/.dmng_profiles

# start a db interactive session
db:
	@ sqlite3 ~/.config/dmng/profiles/profiles-DB.sql
