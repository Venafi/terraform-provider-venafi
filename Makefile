###Metadata about this makefile and position
MKFILE_PATH := $(lastword $(MAKEFILE_LIST))
CURRENT_DIR := $(patsubst %/,%,$(dir $(realpath $(MKFILE_PATH))))


#Plugin information
PLUGIN_NAME := terraform-provider-venafi
PLUGIN_DIR := pkg/bin
PLUGIN_PATH := $(PLUGIN_DIR)/$(PLUGIN_NAME)
DIST_DIR := pkg/dist
ifdef BUILD_NUMBER
	VERSION=`git describe --abbrev=0 --tags`+$(BUILD_NUMBER)
else
	VERSION=`git describe --abbrev=0 --tags`
endif

TEST?=$$(go list ./... |grep -v 'vendor')
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)

all: build test testacc


#Build
build:
	env CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags '-s -w -extldflags "-static"' -a -o $(PLUGIN_DIR)/linux/$(PLUGIN_NAME) || exit 1
	env CGO_ENABLED=0 GOOS=linux   GOARCH=386   go build -ldflags '-s -w -extldflags "-static"' -a -o $(PLUGIN_DIR)/linux86/$(PLUGIN_NAME) || exit 1
	env CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags '-s -w -extldflags "-static"' -a -o $(PLUGIN_DIR)/darwin/$(PLUGIN_NAME) || exit 1
	env CGO_ENABLED=0 GOOS=darwin  GOARCH=386   go build -ldflags '-s -w -extldflags "-static"' -a -o $(PLUGIN_DIR)/darwin86/$(PLUGIN_NAME) || exit 1
	env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags '-s -w -extldflags "-static"' -a -o $(PLUGIN_DIR)/windows/$(PLUGIN_NAME).exe || exit 1
	env CGO_ENABLED=0 GOOS=windows GOARCH=386   go build -ldflags '-s -w -extldflags "-static"' -a -o $(PLUGIN_DIR)/windows86/$(PLUGIN_NAME).exe || exit 1
	chmod +x $(PLUGIN_DIR)/*

compress:
	mkdir -p $(DIST_DIR)
	rm -f $(DIST_DIR)/*
	zip -j "${CURRENT_DIR}/$(DIST_DIR)/${PLUGIN_NAME}_${VERSION}_linux.zip" "$(PLUGIN_DIR)/linux/$(PLUGIN_NAME)" || exit 1
	zip -j "${CURRENT_DIR}/$(DIST_DIR)/${PLUGIN_NAME}_${VERSION}_linux86.zip" "$(PLUGIN_DIR)/linux86/$(PLUGIN_NAME)" || exit 1
	zip -j "${CURRENT_DIR}/$(DIST_DIR)/${PLUGIN_NAME}_${VERSION}_darwin.zip" "$(PLUGIN_DIR)/darwin/$(PLUGIN_NAME)" || exit 1
	zip -j "${CURRENT_DIR}/$(DIST_DIR)/${PLUGIN_NAME}_${VERSION}_darwin86.zip" "$(PLUGIN_DIR)/darwin86/$(PLUGIN_NAME)" || exit 1
	zip -j "${CURRENT_DIR}/$(DIST_DIR)/${PLUGIN_NAME}_${VERSION}_windows.zip" "$(PLUGIN_DIR)/windows/$(PLUGIN_NAME).exe" || exit 1
	zip -j "${CURRENT_DIR}/$(DIST_DIR)/${PLUGIN_NAME}_${VERSION}_windows86.zip" "$(PLUGIN_DIR)/windows86/$(PLUGIN_NAME).exe" || exit 1

collect_artifacts:
	rm -rf artifcats
	mkdir -p artifcats
	mv $(PLUGIN_DIR)/linux/$(PLUGIN_NAME) artifcats/$(PLUGIN_NAME)_v$(VERSION)_linux
	mv $(PLUGIN_DIR)/linux86/$(PLUGIN_NAME) artifcats/$(PLUGIN_NAME)_v$(VERSION)_linux86
	mv $(PLUGIN_DIR)/darwin/$(PLUGIN_NAME) artifcats/$(PLUGIN_NAME)_v$(VERSION)_darwin
	mv $(PLUGIN_DIR)/darwin86/$(PLUGIN_NAME) artifcats/$(PLUGIN_NAME)_v$(VERSION)_darwin86
	mv $(PLUGIN_DIR)/windows/$(PLUGIN_NAME).exe artifcats/$(PLUGIN_NAME)_v$(VERSION)_windows.exe
	mv $(PLUGIN_DIR)/windows86/$(PLUGIN_NAME).exe artifcats/$(PLUGIN_NAME)_v$(VERSION)_windows86.exe
	cd artifcats; sha1sum * > hashsums.sha1

clean:
	rm -fv terraform.tfstate*
	rm -fv $(PLUGIN_NAME)
	rm -rfv $(PLUGIN_DIR)/*
	rm -rfv $(DIST_DIR)/*
	rm -rfv .terraform

dev: clean fmtcheck
	go test ./...
	go build
	terraform init

test: fmtcheck test_go testacc test_e2e

test_go:
	go test -i $(TEST) || exit 1
	echo $(TEST) | \
		xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4
testacc:
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m

fmt:
	gofmt -w $(GOFMT_FILES)

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

#Integration tests using real terrafomr binary
test_e2e: test_e2e_dev test_e2e_tpp test_e2e_cloud

test_e2e_tpp:
	echo yes|terraform apply -target=venafi_certificate.tpp_certificate
	terraform state show venafi_certificate.tpp_certificate
	terraform output cert_certificate_tpp > /tmp/cert_certificate_tpp.pem
	terraform output cert_private_key_tpp > /tmp/cert_private_key_tpp.pem
	cat /tmp/cert_certificate_tpp.pem
	cat /tmp/cert_certificate_tpp.pem|openssl x509 -inform pem -noout -issuer -serial -subject -dates

test_e2e_cloud:
	echo yes|terraform apply -target=venafi_certificate.cloud_certificate
	terraform state show venafi_certificate.cloud_certificate
	terraform output cert_certificate_cloud > /tmp/cert_certificate_cloud.pem
	cat /tmp/cert_certificate_cloud.pem
	cat /tmp/cert_certificate_cloud.pem|openssl x509 -inform pem -noout -issuer -serial -subject -dates

test_e2e_dev:
	echo yes|terraform apply -target=venafi_certificate.dev_certificate
	terraform state show venafi_certificate.dev_certificate
	terraform output cert_certificate_dev > /tmp/cert_certificate_dev.pem
	cat /tmp/cert_certificate_dev.pem
	cat /tmp/cert_certificate_dev.pem|openssl x509 -inform pem -noout -issuer -serial -subject -dates
	terraform output cert_private_key_dev > /tmp/cert_private_key_dev.pem
	cat /tmp/cert_private_key_dev.pem

test_e2e_dev_ecdsa:
	echo yes|terraform apply -target=venafi_certificate.dev_certificate_ecdsa
	terraform state show venafi_certificate.dev_certificate_ecdsa
	terraform output cert_certificate_dev_ecdsa > /tmp/cert_certificate_dev_ecdsa.pem
	cat /tmp/cert_certificate_dev_ecdsa.pem
	cat /tmp/cert_certificate_dev_ecdsa.pem|openssl x509 -inform pem -noout -issuer -serial -subject -dates
	terraform output cert_private_key_dev_ecdsa > /tmp/cert_private_key_dev_ecdsa.pem
	cat /tmp/cert_private_key_dev_ecdsa.pem
