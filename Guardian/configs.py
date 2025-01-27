import os
import csv
import configparser
from enum import Enum

HistoryConf = Enum("HistoryConf", ["SPLIT", "ALL", "NONE", "PROCESSED"])
HISTORY: HistoryConf = HistoryConf.NONE

InformationDistillationConf = Enum(
    "InformationDistillation", ["CHATGPT", "SCRIPT", "NONE"]
)
INFODISTILL: InformationDistillationConf = InformationDistillationConf.CHATGPT

# GenerationConf = Enum('GenerationConf', ['INTERACTIVE', 'SELFPLANNING', 'ONEHOP','BACKTRACK',"STATICFDTREE","NOPRUNE",'NOBACKTRACK',"DFSBACKTRACK","LOCALBACKTRACK","GLOBALBACKTRACK"])
# GENERATION: GenerationConf = GenerationConf.INTERACTIVE


def init():
    pass
    """
    global apk_info

    apk_info = {
        line["apk_name"]: {
            "package": line["package_name"],
            "username": line["username"],
            "password": line["password"],
        }
        for line in reader
    }
    """


init()
