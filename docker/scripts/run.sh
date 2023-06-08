#!/bin/bash

docker run -it  -v $HOME:/root stevemcquaid/stoken:latest stoken $@

