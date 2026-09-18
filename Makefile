.PHONY: dashboard run-exfil run-net run-escape run-benign test smoke policies clean

dashboard:      ## launch the live web dashboard (needs sudo)
	sudo python3 -m cerberus.web

run-exfil:      ## CLI: credential-exfil villain
	sudo python3 -m cerberus.cli run -s payloads/exfil_credentials.py

run-net:        ## CLI: network-exfil villain under loopback policy
	sudo python3 -m cerberus.cli run -p loopback --net host -s payloads/exfil_network.py

run-escape:     ## CLI: sandbox-escape villain
	sudo python3 -m cerberus.cli run -s payloads/escape_attempt.py

run-benign:     ## CLI: benign control (should be CLEAN)
	sudo python3 -m cerberus.cli run -s payloads/benign_wordcount.py

test:           ## full integration suite
	sudo python3 tests/integration.py

smoke:          ## seccomp user-notify smoke test
	sudo python3 tests/smoke_notify.py

policies:       ## list policy profiles
	python3 -m cerberus.cli policies

clean:
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

appimage:       ## build the portable Linux AppImage (needs appimagetool in packaging/)
	cd packaging && ./build_appimage.sh ..

native:         ## run the native Tkinter desktop app (needs python3-tk)
	./run-native.sh

appimage-native: ## build the native-GUI AppImage (run on a host with python3-tk)
	cd packaging && ./build_appimage_native.sh ..

harden-test:    ## run the hardening regression suite
	sudo python3 tests/hardening.py

vm:             ## run Cerberus inside a disposable QEMU VM (needs qemu)
	python3 -m cerberus.vm run

vm-dry:         ## preview the QEMU command and validate the seed (no boot)
	python3 -m cerberus.vm run --dry-run
