from Infra.hierarchy import (
    SemanticHierarchy,
    TotalVisibleHierarchy,
    VisibleHierarchy,
    Hierarchy,
)
from typing import List, Tuple, Callable
from Infra.infra import TestCase, EventSeq, Event, Widget
from configs import *
from ExecutionEngine.screen_control import AndroidController
import Infra.util as util
import ExecutionEngine.chatgpt as chatgpt
import time
from collections import defaultdict


class Context:
    """
    A context is a UI state maintains the following information:
    - activity: the current activity
    - hierarchy: the processed hierarchy of the current activity, containing interactable UI actions used for UI state hashing.
    - bannedEvents: the disabled events based on domain knowledge.
    - event: the selected UI event in this UI state; disallow repeated selection.
    """

    hierarchy: Hierarchy
    activity: str
    bannedEvents = List[Event]
    target: str

    def __init__(self, activity: str, target: str, hierarchy: Hierarchy):
        self.target = target
        self.hierarchy = hierarchy
        self.activity = activity
        self.event = None
        self.bannedEvents = []
        self.initial_prompt = (
            "Suppose you are an Android UI testing expert helping me interact with an Android application. "
            "During my interaction, I happen to be stuck in front of a screen that I did not expect and I need your help. "
            "In our conversation, each round I will provide you with a list of UI elements on the screen, "
            "and your task is to select one and only one UI element with its index that is the most likely to reach "
            "the test target.\n"
            "When choosing the UI element, please remeber to prioritize a forward based exploration of the application "
            'and to limit the use of the "back" or "cancel" functions (or analogous UI elements) to the minimum (ideally never).'
            "Instead, attempt to always choose UI elements that confirm current configurations. "
            'For instance, if a screen has UI elements with text corresponding to "OK" or "Confirm", choose them.\n'
        )

    def setRelevant(self):
        """
        Filter textual information with rule-based heuristics or LLM-based heuristics.
        """
        if INFODISTILL == InformationDistillationConf.CHATGPT:
            self.setTextRelevant()
            self.setContentDescRelevant()
        else:
            for w in self.hierarchy:
                w.contentDescRelevant = (
                    True if w.contentDesc.strip() != "" else False
                )
                w.textRelevant = (
                    True if w.contentDescRelevant is not True else False
                )

    def setTextRelevant(self):
        texts = list({w.text for w in self.hierarchy if w.text.strip() != ""})
        if len(texts) == 0:
            return

        textMapping = {t: set() for t in texts}
        for idx, w in enumerate(self.hierarchy):
            if w.text.strip() != "":
                textMapping[w.text].add(idx)
        interestingTextConsts = ["OFF", "ON"]
        if any(
            [
                not util.isInteger(s) and s not in interestingTextConsts
                for s in texts
            ]
        ):
            interestingTexts = list(
                filter(
                    lambda s: util.isInteger(s) or s in interestingTextConsts,
                    texts,
                )
            )
            texts = list(
                filter(
                    lambda s: not util.isInteger(s)
                    and s not in interestingTextConsts,
                    texts,
                )
            )
            elemTexts = [f"{idx}. " + m for idx, m in enumerate(texts)]

            description = (
                f"Currently we have {len(elemTexts)} texts:\n"
                + "\n".join(elemTexts)
            )
            task = f"Remember that your task is to {self.target}. "
            prompt = "\n".join([description, "", task])
            interestingTexts.extend(
                [
                    texts[idx]
                    for idx in chatgpt.Session(
                        [("system", self.initial_prompt)]
                    ).queryListOfIndex(prompt, lambda x: x < len(texts))
                ]
            )
        else:
            interestingTexts = texts

        for text in interestingTexts:
            for i in textMapping[text]:
                self.hierarchy[i].textRelevant = True

    def setContentDescRelevant(self):
        descMapping = [
            (w.contentDesc, idx)
            for idx, w in enumerate(self.hierarchy)
            if w.contentDesc.strip() != ""
        ]
        if len(descMapping) == 0:
            return
        elemDescs = [f"{idx}. " + m[0] for idx, m in enumerate(descMapping)]

        description = (
            f"Currently we have {len(elemDescs)} texts:\n"
            + "\n".join(elemDescs)
        )
        task = f"Remember that your task is to {self.target}. "
        prompt = "\n".join([description, "", task])

        for idx in chatgpt.Session(
            [("system", self.initial_prompt)]
        ).queryListOfIndex(prompt, lambda x: x < len(descMapping)):
            self.hierarchy[descMapping[idx][1]].contentDescRelevant = True
        for w in self.hierarchy:
            if "ImageButton" in w.clazz:
                w.contentDescRelevant = True

    def setEvent(self, event: Event):
        self.event = event

    # get all available events (remove banned ones)
    def getEvents(self) -> List[Event]:
        if INFODISTILL in [
            InformationDistillationConf.SCRIPT,
            InformationDistillationConf.CHATGPT,
        ]:
            events = self.hierarchy.getEvents()
            # TODO: add unique
            return list(filter(lambda x: x not in self.bannedEvents, events))
        raise NotImplementedError()

        # SHUFFLE
        # shuffle(events)

    def __eq__(self, other: "Context"):
        # print("checking context equal")

        def isVisible(node):
            return all(
                node.get(p) == "true" for p in ["focusable", "visible-to-user"]
            )

        if (
            self.activity is not None
            and other.activity is not None
            and self.activity != other.activity
        ):
            #  print(self.activity, other.activity)
            return False

        ui_hash_set = {hash(widget) for widget in self.hierarchy}
        cur_hash_set = {hash(widget) for widget in other.hierarchy}
        # print(ui_hash_set, cur_hash_set)
        # print(list(map(lambda x: x.attrib, self.hierarchy)), list(map(lambda x: x.attrib, other.hierarchy)))
        """
        print(
            len(ui_hash_set),
            len(cur_hash_set),
            len(cur_hash_set & ui_hash_set),
        )
        """
        if (
            len(cur_hash_set & ui_hash_set) / len(cur_hash_set | ui_hash_set)
            > 0.8
        ):
            # print("context equal")
            # print([w.dumpAsDict() for w in self.hierarchy])
            # print([w.dumpAsDict() for w in other.hierarchy])
            return True
        else:
            return False

    def ban(self, event: Event):
        if event != Event.back():
            self.bannedEvents.append(event)

    def ban_current(self):
        self.ban(self.event)
        self.event = None


class ContextManager:
    contexts: List[Context]
    history: List[Context]
    all_contexts: List[Context]
    all_events: List[Event]

    def __init__(self, pkg: str, app_name: str, target: str):
        self.pkg = pkg
        self.app_name = app_name
        self.target = target

        self.all_contexts = []
        self.history = []
        self.contexts = []
        self.all_events = []
        self.screen_events = []
        self.last_event = None

    def init_context(self, controller):
        self.contexts = []
        self.history = []
        self.all_contexts = []
        self.all_events = []
        self.screen_events = []
        self.last_event = None
        initContext: Context = self.getCurrentContext(controller)
        if len(self.history) == 0:
            self.history.append(initContext)
        self.all_contexts = [initContext]
        self.contexts = [initContext]
        self.contexts[-1].setRelevant()

    def getCurHistory(self) -> List[Event]:
        return [context.event for context in self.contexts[:-1]]

    def getAllHistory(self) -> List[Event]:
        return [context.event for context in self.all_contexts[:-1]]

    def getCurrentContext(self, controller: AndroidController) -> Context:
        return Context(
            controller.app_info()[1],
            self.target,
            SemanticHierarchy(
                self.pkg,
                self.app_name,
                controller.dump(),
                controller.dump(),
            ),
        )

    def get_current_events(self):
        return self.contexts[-1].getEvents()

    def update_history(self, event, activity):
        self.last_event = event
        self.all_events.append(event)
        event_tag = activity + " " + str(event)
        self.screen_events.append(event_tag)
        self.contexts[-1].setEvent(event)

    def get_activity_history(self):
        return self.screen_events

    def PreUpdateContext(self, controller: AndroidController) -> Context:
        currentContext = self.getCurrentContext(controller)
        self.all_contexts.append(currentContext)
        self.history.append(currentContext)
        return currentContext

    def PostUpdateContext(self, currentContext: Context):
        currentContext.setRelevant()
        event: Event = self.contexts[-1].event
        if event:
            if event.action == "text":
                currentContext.ban(event)
        self.contexts.append(currentContext)
