#!/bin/bash
export PYTHONPATH=$PYTHONPATH:$(pwd)
uvicorn main:app --reload --port 8001 