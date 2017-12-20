#!/bin/bash

go get github.com/zmap/go-iptree/iptree

gofmt -s -w main.go

go install github.com/udhos/findcidr
