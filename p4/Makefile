# p4/Makefile
#
# Build the A3E telemetry P4 program for the BMv2 target, and run the
# reference-implementation tests. The P4 compilation requires p4c with
# the BMv2 backend; the tests require pytest and nothing else.

P4C       ?= p4c
TARGET    := bmv2
ARCH      := v1model
BUILD     := build
SRC       := a3e_telemetry/main.p4
P4INFO    := $(BUILD)/a3e_telemetry.p4info.txt
BMV2_JSON := $(BUILD)/a3e_telemetry.json

.PHONY: all clean test compile

all: compile

compile: $(P4INFO) $(BMV2_JSON)

$(BUILD):
	mkdir -p $(BUILD)

$(P4INFO) $(BMV2_JSON): $(SRC) a3e_telemetry/headers.p4 a3e_telemetry/parser.p4 \
                       a3e_telemetry/features.p4 a3e_telemetry/ingress.p4 \
                       a3e_telemetry/egress.p4 | $(BUILD)
	$(P4C) --target $(TARGET) --arch $(ARCH) \
	       --p4runtime-files $(P4INFO) \
	       -o $(BUILD) $(SRC)

test:
	pytest -v tests/

clean:
	rm -rf $(BUILD)
