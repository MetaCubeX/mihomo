NAME=clash
BINDIR=bin
GOBUILD=CGO_ENABLED=0 go build -ldflags '-w -s'

all: linux macos

linux:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

macos:
	GOARCH=amd64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

releases: linux macos
	chmod +x $(BINDIR)/$(NAME)-*
	gzip $(BINDIR)/$(NAME)-linux
	gzip $(BINDIR)/$(NAME)-macos

clean:
	rm $(BINDIR)/*
