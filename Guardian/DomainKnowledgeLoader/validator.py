from ExecutionEngine.screen_control import AndroidController
from Memory.context import ContextManager, Context


def loop_detection(CM: ContextManager, current_Context: Context) -> bool:
    try:
        CM.contexts.index(current_Context)
        return True
    except ValueError:
        return False


def llm_reflection():
    pass


def out_of_app(pkg: str, controller: AndroidController):
    activity = controller.get_activity_name()
    if pkg not in activity:
        return True
    return False
