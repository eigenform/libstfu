# Top-level Makefile
# Build libraries and test binaries

all: libs test
libs:
	@echo "------------------------------------------------"
	@echo "[*] Building libraries ..."
	make -C src/
test: libs
	@echo "------------------------------------------------"
	@echo "[*] Building tests ..."
	make -C tests/
clean:
	@echo "------------------------------------------------"
	@echo "[*] Cleaning build artifacts ..."
	make -C src/ clean
	make -C tests/ clean

.PHONY: clean 
