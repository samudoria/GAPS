from Memory.context import ContextManager, Context


def avoid_repetition():
    pass


def avoid_loop(CM: ContextManager, current_Context: Context):
    contextIdx = CM.contexts.index(current_Context)
    CM.contexts = CM.contexts[: contextIdx + 1]
    CM.contexts[-1].ban_current()


def avoid_out_of_app(CM: ContextManager):
    CM.contexts[-1].ban_current()
