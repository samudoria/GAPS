#!/bin/bash

conda init
conda create -n guardian python=3.8.12 
pip install -r requirements.txt
