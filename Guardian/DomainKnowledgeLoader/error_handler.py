from typing import List
from Infra.infra import Event
from Memory.context import ContextManager


def block_failed_action():
    pass


def restore_state():
    pass


def empty_action_set(events: List[Event], CM: ContextManager):
    if (
        len(
            list(
                filter(
                    lambda x: x[1].strip() != "a View () to click",
                    [(i, e.dump()) for i, e in enumerate(events)],
                )
            )
        )
        < 2
    ):
        CM.contexts[-1].bannedEvents.clear()
        return CM.get_current_events()
    else:
        return CM.get_current_events()
