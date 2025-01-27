import openai
import json
from copy import deepcopy

from typing import List, Set, Dict
from pathlib import Path
import time
import re

from tenacity import (
    retry,
    stop_after_attempt,
    wait_random_exponential,
    retry_if_exception_type,
)  # for exponential backoff

import os


@retry(
    retry=retry_if_exception_type(
        (
            openai.error.APIError,
            openai.error.APIConnectionError,
            openai.error.RateLimitError,
            openai.error.ServiceUnavailableError,
            openai.error.Timeout,
        )
    ),
    wait=wait_random_exponential(multiplier=1, max=60),
    stop=stop_after_attempt(10),
)
def chat_completion_with_backoff(**kwargs):
    response = openai.ChatCompletion.create(**kwargs)
    return response


openai.api_key_path = Path("/home/same/code/speck/gpt_api.key").absolute()
model = "gpt-3.5-turbo"
expensive_model = "gpt-4"
temp = 0.2
system_message: str

history = []
sessions: List["Session"] = []


def getTotalTokensUsed() -> int:
    return sum(
        [
            session.tokens_used["completion"] + session.tokens_used["prompt"]
            for session in sessions
        ]
    )


def setupChatGPT(prompt) -> None:
    global system_message
    system_message = prompt


class Session:
    history: List[tuple]
    tokens_used: Dict[str, int]

    def __init__(self, init_history: List[tuple] = None):
        if init_history is None:
            self.history = [("system", system_message)]
        else:
            self.history = deepcopy(init_history)
        self.tokens_used = {"completion": 0, "prompt": 0}
        sessions.append(self)

    def dump(self, path: Path):
        with open(path, "w") as f:
            json.dump(self.__dict__, f)

    def __iter__(self):
        return iter(self.history)

    def __getitem__(self, item):
        return self.history[item]

    def transformMessage(self, messages):
        return [{"role": t, "content": m} for (t, m) in messages]

    def updateTokensUsed(self, usage: Dict[str, int]):
        self.tokens_used["completion"] += usage["completion_tokens"]
        self.tokens_used["prompt"] += usage["prompt_tokens"]

    def __call__(self, message):
        # print(self.history)
        self.history.append(("user", message))
        print(message)
        resp = chat_completion_with_backoff(
            model=model,
            messages=self.transformMessage(self.history),
            temperature=temp,
        )
        self.updateTokensUsed(resp["usage"])
        response = resp["choices"][0]["message"]["content"]
        print("=" * 20)
        self.history.append(("assistant", response))
        print(response)
        return response

    def findFirstInteger(self, s: str):
        if re.search(r"\d+", s) is None:
            return None
        return int(re.search(r"\d+", s).group())

    def queryIndex(self, prompt="", limit=lambda x: True) -> int:
        prompt += (
            "Please choose only one UI element with its index such that the element can make us closer to our test target."
            + "\nIf none of the UI element can do so, respond with index-none."
        )
        response = self(prompt)
        print("In queryIndex: ", response)
        for m in re.finditer("index-", response):
            local = response[m.start() : m.start() + 12]
            if "index-none" not in local and limit(
                self.findFirstInteger(local[5:])
            ):
                return self.findFirstInteger(local[5:])
        return -1
        # if 'index-none' in response:
        #    return -1
        # raise NotImplementedError("How to deal with the situation where chatgpt cannot give any index?")

    def queryOpinion(self, prompt="") -> bool:
        prompt += "Please response in YES or NO, one word only."
        response = self(prompt)
        return "YES" in response or (
            "NO" not in response and "yes" in response
        )

    def queryListOfIndex(self, prompt="", guard=lambda x: True) -> Set[int]:
        prompt += (
            "Please select a list of indexes for the texts that you think are very very relevant to the goal.\n"
            + "Please return in the form [0,1,2] or return nothing is none of the texts are relevant."
            "Remember, only select the ones that are relevant. It is ok to select nothing."
        )
        response = self(prompt)
        try:
            strList: str = response[
                response.index("[") : response.index("]") + 1
            ]
            return set(
                filter(
                    guard,
                    map(lambda x: int(strList.strip()), strList.split(",")),
                )
            )
        except:
            print(
                "No list is find in the response. Fall back to using regex and grab all the numbers."
            )
            return set(
                filter(
                    guard,
                    [
                        int(number.strip())
                        for number in re.findall(r"\d+", response)
                    ],
                )
            )

    def queryString(self, prompt="") -> str:
        prompt += " Please only respond with the text input and nothing else."
        response = self(prompt)

        def extract_str(res: str):
            if sum([ch == '"' for ch in response]) >= 2:
                res = res.split('"')[1]
            elif sum([ch == "'" for ch in response]) >= 2:
                res = res.split("'")[1]
            return res

        return extract_str(response)

    def clear_last(self):
        self.history = self.history[:-2]

    def record_history(self):
        Path("chatgpt_android/history").mkdir(exist_ok=True)
        cur_time = time()
        with open(
            f"chatgpt_android/history/history-{cur_time}.json", "w"
        ) as f:
            json.dump(self.full_history, f)
        print(f"History saved to history-{cur_time}")


if __name__ == "__main__":
    setupChatGPT("")
    testsession = Session()
