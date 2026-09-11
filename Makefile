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
	elfsign --sign $(BINARY)
	cimatrix-gate --elf $(BINARY)
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
