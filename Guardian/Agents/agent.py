import ExecutionEngine.chatgpt as chatgpt
from configs import *
import Infra.util as util
from Infra.hierarchy import (
    SemanticHierarchy,
    TotalVisibleHierarchy,
    VisibleHierarchy,
)
from ExecutionEngine.screen_control import AndroidController
from typing import List, Tuple, Callable
from Infra.infra import TestCase, EventSeq, Event, Widget
from Memory.context import Context
import re


class Agent:
    """
    Represents an LLM agent for Android UI testing.
    Attributes:
    - app (str): The name of the app under test.
    - target (str): The testing objective.
    - initial_prompt (str): The initial prompt for the conversation with the LLM.
    - first_prompt (str): The first prompt for the conversation with the LLM, including the app name and testing target.
    - targetPrompt (str): The prompt reminding the LLM of the testing objective.
    - session (chatgpt.Session): The chatGPT session for the conversation with the LLM.
    Methods:
    - __init__(self, _app, _pkg, _target: str): Initializes the Agent object.
    - act(self, events: List[Event]): Performs an action based on the given events.
    - obtain_event_to_execute(self, events: List[Event]): Obtains the event to execute based on the given events.
    - getInput(self, target) -> str: Asks chatGPT for the text input.
    """

    def __init__(self, app_name, target: str):
        self.app_name = app_name
        self.testing_objective = target
        self.initial_prompt = (
            "Suppose you are an Android UI testing expert helping me interact with an Android application. "
            "During my interaction, I happen to be stuck in front of a screen that I did not expect and I need your help. "
            "In our conversation, each round I will provide you with a list of UI elements on the screen, "
            "and your task is to select one and only one UI element with its index that is the most likely to reach "
            "the test target.\n"
        )

        self.exploration_strategy = (
            "When choosing the UI element, please remeber to prioritize a forward based exploration of the application "
            'and to limit the use of the "back" or "cancel" functions (or analogous UI elements) to the minimum (ideally never).'
            "Instead, attempt to always choose UI elements that confirm current configurations. "
            'For instance, if a screen has UI elements with text corresponding to "OK" or "Confirm", choose them.\n'
        )

        self.first_prompt = (
            self.initial_prompt
            + self.exploration_strategy
            + f"We are testing the {self.app_name} app . "
            + f"Our testing target is to {self.testing_objective}ff."
        )

        self.targetPrompt = f"Remember our test target is to {self.testing_objective} on {self.app_name}."
        chatgpt.setupChatGPT(self.first_prompt)
        self.session = None
        # self.session = chatgpt.Session()

    def plan(self, events: List[Event], activity, activity_history):
        event = self.obtain_event_to_execute(
            events, activity, activity_history
        )
        if event.action == "text":
            event.input = self.getInput(self.testing_objective)
        return event

    def obtain_event_to_execute(
        self, events: List[Event], current_activity, activity_history
    ):

        filteredEvents = list(
            filter(
                lambda x: x[1].strip() != "a View () to click",
                [(i, e.dump()) for i, e in enumerate(events)],
            )
        )
        # remove previous actions performed in the same activity
        for i, filteredEvent in filteredEvents:
            for action_widget in activity_history:

                splits = action_widget.split()
                print(splits)
                if len(splits) > 3:
                    activity, action, widget = splits[:3]
                elif len(splits) == 3:
                    activity, action, widget = splits
                else:
                    activity, action = splits
                    widget = action
                if (
                    activity == current_activity
                    and f"resource_id {widget}" in filteredEvent
                    and f"to {action}" in filteredEvent
                    and filteredEvent in filteredEvents
                ):
                    filteredEvents.remove(filteredEvent)

        elemDesc = [f"index-{i}: {x[1]}" for i, x in enumerate(filteredEvents)]
        event_map = {i: e[0] for i, e in enumerate(filteredEvents)}

        description = (
            f'Currently we are in a screen named "{current_activity}" and we have {len(elemDesc)} widgets, namely:\n'
            + "\n".join(elemDesc)
        )

        task = self.targetPrompt
        latest_actions = activity_history
        if len(latest_actions) > 3:
            latest_actions = latest_actions[:3]
        history = (
            f"The user has recently performed {len(latest_actions)} actions:\n"
            + "\n".join(latest_actions)
        )
        prompt = "\n".join(
            [description, self.exploration_strategy, history, task]
        )
        self.session = chatgpt.Session()
        print(prompt)
        idx = self.session.queryIndex(
            prompt, lambda x: x in range(len(events))
        )
        print(idx)

        """
        if HISTORY == HistoryConf.ALL:
            historyDesc = [f"- {e.dump()}" for e in self.getAllHistory()]
            history = (
                f"The user has performed {len(historyDesc)} actions:\n"
                + "\n".join(historyDesc)
            )
            description += "\n\n" + history
        elif HISTORY == HistoryConf.PROCESSED:
            historyDesc = [f"- {e.dump()}" for e in self.getCurHistory()]
            history = (
                f"The user has performed {len(historyDesc)} actions:\n"
                + "\n".join(historyDesc)
            )
            description += "\n\n" + history
        """
        if idx == -1:
            return Event.back()
        return events[event_map[idx]]

    def getInput(self, target) -> str:
        # ask chatGPT what text to input
        task = (
            "You have selected a TextEdit view, which requires a text input."
            f"Remember that your task is to {target}"
        )
        requirement = (
            "Please insert the text that you want to input."
            "Please only respond with the text input and nothing else."
        )
        return self.session.queryString(f"{task}\n{requirement}")
