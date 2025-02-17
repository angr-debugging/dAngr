#!/bin/bash
#run docker and pass all args
docker run -it -p 8000:8000 -v $(pwd):/workspace dangr $@ 