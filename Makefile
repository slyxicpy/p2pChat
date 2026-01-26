CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -I include
LDFLAGS = -lssl -lcrypto -lpthread

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
LIB_DIR = lib
PY_DIR = python

CRYPTO_LIB = $(LIB_DIR)/libcrypto.so
PROTOCOL_LIB = $(LIB_DIR)/libprotocol.so
NETWORK_LIB = $(LIB_DIR)/libnetwork.so

PORT ?= 8888
USERNAME ?= user
PASSWORD ?= pass
ONION ?= localhost

VENV_DIR = venv
VENV_PYTHON = $(VENV_DIR)/bin/python3
VENV_PIP = $(VENV_DIR)/bin/pip3

OS_DETECTED := $(shell uname -s)
DISTRO := $(shell if [ -f /etc/os-release ]; then . /etc/os-release; echo $$ID; else echo unknown; fi)

.PHONY: all clean clean-all install venv help check rebuild
.PHONY: run-server run-client run-p2p genkey test-local test-tor status

all: setup $(CRYPTO_LIB) $(PROTOCOL_LIB) $(NETWORK_LIB)
	@echo "[build complete]"
	@echo "[libs] crypto :: protocol :: network"

setup:
	@mkdir -p $(BUILD_DIR) $(LIB_DIR)

$(CRYPTO_LIB): $(SRC_DIR)/crypto.c $(INC_DIR)/crypto.h | setup
	@echo "[building] libcrypto.so..."
	@$(CC) -shared $(CFLAGS) $< -o $@ $(LDFLAGS)

$(PROTOCOL_LIB): $(SRC_DIR)/protocol.c $(INC_DIR)/protocol.h | setup
	@echo "[building] libprotocol.so..."
	@$(CC) -shared $(CFLAGS) $< -o $@ $(LDFLAGS)

$(NETWORK_LIB): $(SRC_DIR)/network.c $(INC_DIR)/network.h $(INC_DIR)/protocol.h | setup
	@echo "[building] libnetwork.so..."
	@$(CC) -shared $(CFLAGS) $< -o $@ $(LDFLAGS)

venv:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "[creating venv]"; \
		python3 -m venv $(VENV_DIR); \
	fi
	@echo "[installing deps]"
	@$(VENV_PIP) install --upgrade pip > /dev/null 2>&1
	@if [ -f requirements.txt ]; then \
		$(VENV_PIP) install -r requirements.txt > /dev/null 2>&1; \
	else \
		$(VENV_PIP) install PySocks > /dev/null 2>&1; \
	fi
	@echo "[done]"

install: venv
	@echo "[installing deps] $(DISTRO)"
	@if [ "$(DISTRO)" = "void" ]; then \
		sudo xbps-install -Sy base-devel openssl-devel tor; \
	elif [ "$(DISTRO)" = "ubuntu" ] || [ "$(DISTRO)" = "debian" ]; then \
		sudo apt update && sudo apt install -y build-essential libssl-dev tor; \
	elif [ "$(DISTRO)" = "arch" ] || [ "$(DISTRO)" = "manjaro" ]; then \
		sudo pacman -S --noconfirm base-devel openssl tor; \
	elif [ "$(DISTRO)" = "fedora" ]; then \
		sudo dnf install -y gcc make openssl-devel tor; \
	elif [ "$(PREFIX)" != "" ]; then \
		pkg install -y clang openssl tor; \
	else \
		echo "[err] unknown distro"; \
		echo "install :: build-essential openssl-devel tor"; \
		exit 1; \
	fi
	@echo "[done]"

clean:
	@echo "[cleaning]"
	@rm -rf $(BUILD_DIR)/* $(LIB_DIR)/*
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.so" ! -path "./$(LIB_DIR)/*" -delete
	@echo "[clean]"

clean-all: clean
	@echo "[removing venv]"
	@rm -rf $(VENV_DIR)
	@echo "[clean all]"

run-server:
	@if [ ! -d "$(VENV_DIR)" ]; then echo "[err] venv not found :: make venv"; exit 1; fi
	@echo "[starting server] $(PORT)"
	@$(VENV_PYTHON) $(PY_DIR)/server.py -p $(PORT) -P $(PASSWORD) -s

run-client:
	@if [ ! -d "$(VENV_DIR)" ]; then echo "[err] venv not found :: make venv"; exit 1; fi
	@echo "[connecting] $(ONION):$(PORT) as $(USERNAME)"
	@$(VENV_PYTHON) $(PY_DIR)/client.py -o $(ONION) -p $(PORT) -u $(USERNAME) -P $(PASSWORD)

run-p2p:
	@if [ ! -d "$(VENV_DIR)" ]; then echo "[err] venv not found :: make venv"; exit 1; fi
	@if [ ! -f "$(LIB_DIR)/libcrypto.so" ]; then echo "[err] libs not compiled :: make all"; exit 1; fi
	@$(VENV_PYTHON) $(PY_DIR)/p2pNode.py -u $(USERNAME) -P $(PASSWORD) -p $(PORT) $(ARGS)

genkey:
	@if [ ! -d "$(VENV_DIR)" ]; then echo "[err] venv not found :: make venv"; exit 1; fi
	@$(VENV_PYTHON) $(PY_DIR)/p2pNode.py --genkey

test-local:
	@echo "[testing local] no tor required"
	@echo ""
	@echo "t1 :: make run-p2p USERNAME=maxSteel PASSWORD=testedByx PORT=8888 ARGS='--verify --local'"
	@echo "t2 :: make run-p2p USERNAME=bosNax PASSWORD=testedByx PORT=8889 ARGS='--verify --local -b 127.0.0.1:8888'"
	@echo ""

test-tor:
	@echo "[testing tor]"
	@if ! pgrep -x tor > /dev/null; then \
		echo "[err] tor not running"; \
		echo "start :: sudo systemctl start tor"; \
		exit 1; \
	fi
	@echo "[tor running]"
	@echo ""
	@echo "t1 :: make run-p2p USERNAME=alix PASSWORD=testedByx PORT=8888 ARGS='--verify -o your.onion'"
	@echo "t2 :: make run-p2p USERNAME=bones PASSWORD=testedByx PORT=8889 ARGS='--verify -b alice.onion:8888'"
	@echo ""

check:
	@echo "[checking syntax]"
	@$(CC) $(CFLAGS) -fsyntax-only $(SRC_DIR)/crypto.c && echo "[ok] crypto.c"
	@$(CC) $(CFLAGS) -fsyntax-only $(SRC_DIR)/protocol.c && echo "[ok] protocol.c"
	@$(CC) $(CFLAGS) -fsyntax-only $(SRC_DIR)/network.c && echo "[ok] network.c"

rebuild: clean all

status:
	@echo "[status]"
	@echo ""
	@echo "system   :: $(OS_DETECTED) [$(DISTRO)]"
	@echo ""
	@if [ -f "$(CRYPTO_LIB)" ]; then echo "libcrypto    :: ok"; else echo "libcrypto    :: missing [make all]"; fi
	@if [ -f "$(PROTOCOL_LIB)" ]; then echo "libprotocol  :: ok"; else echo "libprotocol  :: missing [make all]"; fi
	@if [ -f "$(NETWORK_LIB)" ]; then echo "libnetwork   :: ok"; else echo "libnetwork   :: missing [make all]"; fi
	@echo ""
	@if [ -d "$(VENV_DIR)" ]; then echo "venv         :: ok"; else echo "venv         :: missing [make venv]"; fi
	@if [ -d "$(VENV_DIR)" ]; then \
		if $(VENV_PYTHON) -c "import socks" 2>/dev/null; then echo "pysocks      :: ok"; else echo "pysocks      :: missing [make venv]"; fi; \
	fi
	@echo ""
	@if pgrep -x tor > /dev/null; then echo "tor          :: running"; else echo "tor          :: not running"; fi
	@echo ""

help:
	@echo ""
	@echo "[p2pChat] makefile help"
	@echo ""
	@echo "setup"
	@echo "  make install       install deps + venv"
	@echo "  make all           compile libs"
	@echo "  make venv          create venv"
	@echo "  make status        check status"
	@echo ""
	@echo "build"
	@echo "  make all           compile all"
	@echo "  make clean         clean builds"
	@echo "  make clean-all     clean all + venv"
	@echo "  make rebuild       clean + build"
	@echo "  make check         check syntax"
	@echo ""
	@echo "run p2p"
	@echo "  make run-p2p USERNAME=user PASSWORD=secx PORT=8888"
	@echo "  make run-p2p USERNAME=user PASSWORD=secx ARGS='--verify -o host.onion'"
	@echo "  make run-p2p USERNAME=user ARGS='-b host.onion:8888 --verify'"
	@echo ""
	@echo "utils"
	@echo "  make genkey        generate secure key"
	@echo "  make test-local    test without tor"
	@echo "  make test-tor      test with tor"
	@echo ""
	@echo "legacy"
	@echo "  make run-server PASSWORD=secx PORT=8888"
	@echo "  make run-client ONION=addr.onion USERNAME=bones PASSWORD=secx"
	@echo ""
	@echo "examples"
	@echo ""
	@echo "  quick test local"
	@echo "    t1 :: make run-p2p USERNAME=lilnes PASSWORD=test ARGS='--local'"
	@echo "    t2 :: make run-p2p USERNAME=bones PASSWORD=test PORT=8889 ARGS='--local -b 127.0.0.1:8888'"
	@echo ""
	@echo "  secure with fingerprint"
	@echo "    make genkey"
	@echo "    make run-p2p USERNAME=alice ARGS='-k <KEY> --verify -o addr.onion'"
	@echo ""
	@echo "  connect to peer"
	@echo "    make run-p2p USERNAME=bones PASSWORD=secx ARGS='-b addr.onion:8888 --verify'"
	@echo ""
	@echo "detected :: $(DISTRO) on $(OS_DETECTED)"
	@echo ""

.DEFAULT_GOAL := help
