GOCMD=go
XGOCMD=xgo -go=go-1.17.x
GOBUILD=CGO_ENABLED=1 $(GOCMD) build -trimpath
GOCLEAN=$(GOCMD) clean
NAME=clash
BINDIR=$(shell pwd)/bin
VERSION=$(shell git describe --tags --always 2>/dev/null ||  date +%F)
BUILDTIME=$(shell date -u)
BUILD_PACKAGE=.
RELEASE_LDFLAGS='-X "github.com/Dreamacro/clash/constant.Version=$(VERSION)" \
                		-X "github.com/Dreamacro/clash/constant.BuildTime=$(BUILDTIME)" \
                		-w -s -buildid='
STATIC_LDFLAGS='-X "github.com/Dreamacro/clash/constant.Version=$(VERSION)" \
               		-X "github.com/Dreamacro/clash/constant.BuildTime=$(BUILDTIME)" \
               		-extldflags "-static" \
               		-w -s -buildid='

PLATFORM_LIST = \
	darwin-amd64 \
	darwin-arm64 \
	linux-amd64 \
	linux-arm64
#	linux-386

WINDOWS_ARCH_LIST = \
	windows-amd64 \
	windows-386
#	windows-arm64

all: linux-amd64 darwin-amd64 windows-amd64 # Most used

build:
	$(GOBUILD) -ldflags $(RELEASE_LDFLAGS) -tags build_local -o $(BINDIR)/$(NAME)-$@

darwin-amd64:
	$(XGOCMD) -dest=$(BINDIR) -out=$(NAME) -trimpath=true -ldflags=$(RELEASE_LDFLAGS) -targets=darwin-10.12/amd64 $(BUILD_PACKAGE) && \
	mv $(BINDIR)/$(NAME)-darwin-10.12-amd64 $(BINDIR)/$(NAME)-darwin-amd64

darwin-arm64:
	$(XGOCMD) -dest=$(BINDIR) -out=$(NAME) -trimpath=true -ldflags=$(RELEASE_LDFLAGS) -targets=darwin-11.1/arm64 $(BUILD_PACKAGE) && \
	mv $(BINDIR)/$(NAME)-darwin-11.1-arm64 $(BINDIR)/$(NAME)-darwin-arm64

linux-386:
	$(XGOCMD) -dest=$(BINDIR) -out=$(NAME) -trimpath=true -ldflags=$(STATIC_LDFLAGS) -targets=linux/386 $(BUILD_PACKAGE)

linux-amd64:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -ldflags $(STATIC_LDFLAGS) -o $(BINDIR)/$(NAME)-$@
	#$(XGOCMD) -dest=$(BINDIR) -out=$(NAME) -trimpath=true -ldflags=$(STATIC_LDFLAGS) -targets=linux/amd64 $(BUILD_PACKAGE)

linux-arm64:
	$(XGOCMD) -dest=$(BINDIR) -out=$(NAME) -trimpath=true -ldflags=$(STATIC_LDFLAGS) -targets=linux/arm64 $(BUILD_PACKAGE)

windows-386:
	$(XGOCMD) -dest=$(BINDIR) -out=$(NAME) -trimpath=true -ldflags=$(RELEASE_LDFLAGS) -targets=windows-4.0/386 $(BUILD_PACKAGE) && \
	mv $(BINDIR)/$(NAME)-windows-4.0-386.exe $(BINDIR)/$(NAME)-windows-386.exe

windows-amd64:
	$(XGOCMD) -dest=$(BINDIR) -out=$(NAME) -trimpath=true -ldflags=$(RELEASE_LDFLAGS) -targets=windows-4.0/amd64 $(BUILD_PACKAGE) && \
	mv $(BINDIR)/$(NAME)-windows-4.0-amd64.exe $(BINDIR)/$(NAME)-windows-amd64.exe

#windows-arm64:
#	$(XGOCMD) -dest=$(BINDIR) -out=$(NAME) -trimpath=true -ldflags=$(RELEASE_LDFLAGS) -targets=windows/arm64 $(BUILD_PACKAGE)
#	mv $(NAME)-windows-4.0-arm64.exe $(NAME)-windows-arm64.exe

gz_releases=$(addsuffix .gz, $(PLATFORM_LIST))
zip_releases=$(addsuffix .zip, $(WINDOWS_ARCH_LIST))

$(gz_releases): %.gz : %
	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)

$(zip_releases): %.zip : %
	zip -m -j $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).zip $(BINDIR)/$(NAME)-$(basename $@).exe

all-arch: $(PLATFORM_LIST) $(WINDOWS_ARCH_LIST)

releases: $(gz_releases) $(zip_releases)

clean:
	rm -rf $(BINDIR)/
	mkdir -p $(BINDIR)

cleancache:
	# go build cache may need to cleanup if changing C source code
	$(GOCLEAN) -cache
	rm -rf $(BINDIR)/
	mkdir -p $(BINDIR)