.PHONY: build test dist install doc clean

BINARY    := cmmn-trusted-computing
ASD       := $(BINARY).asd
SBCL_FLAGS := --noinform --non-interactive

build:
	ros init $(BINARY)
	qlot install
	sbcl $(SBCL_FLAGS) \
	  --eval "(require :asdf)" \
	  --eval "(asdf:load-system :cmmn-trusted-computing/core)" \
	  --eval "(sb-ext:save-lisp-and-die \"$(BINARY)\" :executable t :compression t \
	           :toplevel #'cmmn-trusted-computing/core:main)"

test:
	sbcl $(SBCL_FLAGS) \
	  --eval "(require :asdf)" \
	  --eval "(asdf:load-system :cmmn-trusted-computing/tests)" \
	  --eval "(fiveam:run! 'cmmn-trusted-computing/tests::cmmn-trusted-computing-suite)" \
	  --eval "(sb-ext:exit)"

e2e:
	sbcl $(SBCL_FLAGS) \
	  --eval "(require :asdf)" \
	  --eval "(asdf:load-system :cmmn-trusted-computing/e2e)" \
	  --eval "(fiveam:run! 'cmmn-trusted-computing/e2e::e2e-suite)" \
	  --eval "(sb-ext:exit)"

dist: build
	@echo "Stripping DWARF sections..."
	objcopy \
	  --remove-section=.debug_aranges \
	  --remove-section=.debug_info \
	  --remove-section=.debug_abbrev \
	  --remove-section=.debug_line \
	  --remove-section=.debug_str \
	  --remove-section=.debug_loc \
	  --remove-section=.debug_ranges \
	  $(BINARY) $(BINARY)-stripped
	@# Patch the embedded core offset: SBCL stores it as the last 8 bytes
	@python3 -c "\
import struct, os; \
f=open('$(BINARY)-stripped','r+b'); \
f.seek(-8,2); magic=f.read(4); f.seek(-8,2); \
offset=struct.unpack('<Q',f.read(8))[0]; \
orig=os.path.getsize('$(BINARY)'); \
new=os.path.getsize('$(BINARY)-stripped'); \
delta=new-orig; \
f.seek(-8,2); f.write(struct.pack('<Q',offset+delta)); \
f.close(); print(f'Core offset patched: {offset:#x} -> {offset+delta:#x}')"
	mv $(BINARY)-stripped $(BINARY)
	@echo "Signing..."
	elfsign --sign $(BINARY)
	cosign sign $(BINARY)

install:
	sbcl $(SBCL_FLAGS) \
	  --eval "(require :asdf)" \
	  --eval "(asdf:load-system :cmmn-trusted-computing/pipeline)" \
	  --eval '(cmmn-trusted-computing/pipeline:install!)' \
	  --eval "(sb-ext:exit)"

doc:
	mkdir -p build
	sbcl $(SBCL_FLAGS) \
	  --eval "(require :asdf)" \
	  --eval "(asdf:load-system :cmmn-trusted-computing/docs)" \
	  --eval "(cmmn-trusted-computing/docs:render)" \
	  --eval "(sb-ext:exit)"

clean:
	rm -f $(BINARY)
	rm -rf build/
	find . -name "*.fasl" -delete
