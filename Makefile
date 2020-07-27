ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# App name
APP = a_mon

# Flags
CFLAGS += -O3
CFLAGS += -mcmodel=medium
CFLAGS += -DSUPPORT_IPV6

#CFLAGS += -fno-stack-protector

# all source are stored in SRCS-y
SRCS-y := src/traffic_anon.c
SRCS-y += src/ini.c src/process_packet.c src/crypto_ip.c src/rijndael.c src/ip_utils.c src/proto_mng.c src/lru.c src/dns_mng.c src/hash_calculator.c src/proto_finder.c src/tls_mng.c src/flow_mng.c src/http_mng.c
# SRCS-y += src/ini.c src/process_packet.c src/crypto_ip.c src/ip_utils.c
VPATH := src

build: $(SRCS-y)

include $(RTE_SDK)/mk/rte.extapp.mk

