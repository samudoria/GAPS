import time

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
from Memory.context import Context, ContextManager
from Agents.agent import Agent

from DomainKnowledgeLoader.error_handler import (
    block_failed_action,
    restore_state,
    empty_action_set,
)
from DomainKnowledgeLoader.optimizer import (
    avoid_loop,
    avoid_repetition,
    avoid_out_of_app,
)
from DomainKnowledgeLoader.validator import (
    llm_reflection,
    loop_detection,
    out_of_app,
)


class Guardian:
    target_context: Context
    target: str
    controller: AndroidController
    app: str
    pkg: str
    attempt_cnt: int

    def __init__(
        self,
        apk_path,
        target: str,
        _generation_limit: int,
        target_activity: str,
        target_id: str,
    ):
        self.apk_path = apk_path
        self.app_name = util.get_app_name(apk_path)
        self.pkg = util.get_package_name(apk_path)
        self.target = target
        self.target_activity = target_activity
        self.target_id = target_id
        self.agent = Agent(
            self.app_name, self.target
        )  # LLM agent contains the LLM driver
        print(f"[+] ANALYZING {self.app_name}")
        print(f"[+] PACKAGE NAME {self.pkg}")
        self.context_manager = ContextManager(
            self.pkg, self.app_name, self.target
        )  # Context manager is the memory driver
        self.controller = (
            AndroidController()
        )  # Android controller is the UI driver
        self.domain_knowledge = {
            "optimizer": {
                "avoid_loop": avoid_loop,
                "avoid_repetition": avoid_repetition,
                "avoid_out_of_app": avoid_out_of_app,
            },
            "validator": {
                "llm_reflection": llm_reflection,
                "loop_detection": loop_detection,
                "out_of_app": out_of_app,
            },
            "error_handler": {
                "block_failed_action": block_failed_action,
                "restore_state": restore_state,
                "empty_action_set": empty_action_set,
            },
        }
        self.attempt_cnt = 0
        self.generation_limit = _generation_limit

    def mainLoop(self) -> EventSeq:
        if self.domain_knowledge["validator"]["out_of_app"](
            self.pkg, self.controller
        ):
            util.start_app(self.pkg)

        self.context_manager.init_context(self.controller)

        MAX_ALLOW_OUTSIDE = 3

        allow_outside = 0

        while self.attempt_cnt < self.generation_limit:

            events = self.domain_knowledge["error_handler"][
                "empty_action_set"
            ](self.context_manager.get_current_events(), self.context_manager)

            activity = self.controller.get_activity_name()

            activity_history = self.context_manager.get_activity_history()

            event = self.agent.plan(
                events, activity, activity_history
            )  # get the UI event to execute from the LLM agent

            event.act(self.controller)
            self.context_manager.update_history(event, activity)
            time.sleep(1)

            # check if still in app
            if self.domain_knowledge["validator"]["out_of_app"](
                self.pkg, self.controller
            ):
                if allow_outside >= MAX_ALLOW_OUTSIDE:
                    self.domain_knowledge["optimizer"]["avoid_out_of_app"](
                        self.context_manager
                    )
                    util.restart_app(self.pkg)
                    time.sleep(4)
                    allow_outside = 0
                else:
                    allow_outside += 1

            currentContext = self.context_manager.PreUpdateContext(
                self.controller
            )
            # check loop and repetition
            """
            if self.domain_knowledge["validator"]["loop_detection"](
                self.context_manager, currentContext
            ):
                self.domain_knowledge["optimizer"]["avoid_loop"](
                    self.context_manager, currentContext
                )
            else:
                self.context_manager.PostUpdateContext(currentContext)
            """
            """
                title of the app
                text....
                text....
                [ACCEPT]

                here is whats on the screen ordered from top to bottom
                1. name of the app
                2. the text "...."
                3. button with id accept clickable
            """

            self.context_manager.PostUpdateContext(currentContext)

            self.attempt_cnt += 1

            full_activity = self.controller.get_activity_name()
            if self.target_activity and full_activity == self.target_activity:
                if self.target_id:
                    hierarchy = self.controller.dump()
                    for line in hierarchy:
                        if self.target_id in line:
                            return EventSeq(
                                self.context_manager.getCurHistory()
                            )
                else:
                    return EventSeq(self.context_manager.getCurHistory())

        return EventSeq(self.context_manager.getCurHistory())

    def genTestCase(self) -> TestCase:
        return TestCase(self.mainLoop())


if __name__ == "__main__":
    pass
    # INFODISTILL = InformationDistillationConf.NONE
    # app = "Quizlet"
    # pkg = "com.quizlet.quizletandroid"
    # target = "turn on night mode"
    # port = "emulator-5554"
#
# testCase = Guardian(app, pkg, target, port).genTestCase()
# print(testCase._events)
# for event in testCase._events:
#     event.dump(True)
#     print(event)
