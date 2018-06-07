#!/bin/bash

docker run --interactive --tty --volume $HOME:/root \
	stevemcquaid/stoken:latest stoken $@
