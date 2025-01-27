import time, json, traceback
from copy import deepcopy
from typing import List, Set, Tuple, Dict
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element
from ExecutionEngine.screen_control import AndroidController
from pathlib import Path

property_to_event = {
    "clickable": "click",
    # 'long-clickable': 'longclick',
    "scrollable": "swipe",
    # 'checkable': 'check'
}


def parseBound(bounds: str) -> Tuple[int]:
    if bounds is None:
        return None
    left_top, right_bot = bounds.split("][")
    x1, y1 = left_top[1:].split(",")
    x2, y2 = right_bot[:-1].split(",")
    return tuple(map(lambda x: int(x), [x1, y1, x2, y2]))


def posIn(pos: tuple, bound: tuple) -> bool:
    return bound[0] <= pos[0] <= bound[2] and bound[1] <= pos[1] <= bound[3]


class RawHierarchy:
    _hierarchy: Element

    def __init__(self, raw):
        if type(raw) == str:
            self._hierarchy = ET.fromstring(raw)
        else:
            self._hierarchy = raw

    def buildEvent(self, action: str, attribs: dict, *param) -> "Event":
        widget: Widget = self.buildWidget(attribs)
        event: Event = Event(widget, action)
        if action == "text":
            event.input = param[0]
        return event

    def buildWidget(self, attribs: dict):
        try:
            # print(attribs)
            elem = next(
                filter(
                    lambda x: all(
                        [x.get(key) == val for (key, val) in attribs.items()]
                    ),
                    self._hierarchy.iter(),
                )
            )
            return Widget(elem)
        except StopIteration:
            return None

    def dump(self, output: Path):
        ET.ElementTree(self._hierarchy).write(str(output))

    def __eq__(self, other):
        def isVisible(node):
            return all(
                node.get(p) == "true" for p in ["focusable", "visible-to-user"]
            )

        ui_hash_set = {
            hash(Widget(w)) for w in filter(isVisible, self._hierarchy.iter())
        }
        cur_hash_set = {
            hash(Widget(w)) for w in filter(isVisible, other._hierarchy.iter())
        }
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
            return True
        else:
            return False


class Widget:
    pos: tuple
    actionTypes: List[str]
    clazz: str
    resourceId: str
    contentDesc: str
    text: str
    package: str
    attrib: dict

    textRelevant: bool
    contentDescRelevant: bool

    def __init__(self, elem):
        self.attrib = elem.attrib if type(elem) == Element else elem
        self.pos = parseBound(elem.get("bounds"))
        self.actionTypes = [
            property_to_event[p]
            for p in property_to_event
            if elem.get(p) == "true"
        ]
        self.clazz = elem.get("class", "")
        self.resourceId = elem.get("resource-id", "")
        self.contentDesc = elem.get("content-desc", "")
        self.text = elem.get("text", "")
        self.package = elem.get("package", "")
        self.textRelevant = False
        self.contentDescRelevant = False

    def fixTextEdit(self):
        if "EditText" in self.clazz:
            if "click" in self.actionTypes:
                self.actionTypes.remove("click")
            self.actionTypes.append("text")

    def isScroll(self) -> bool:
        return "ScrollView" in self.clazz or "swipe" in self.actionTypes

    def dump(self):
        description = []
        if self.contentDescRelevant:
            description.append(
                f"accessibility information: {self.contentDesc}"
            )
        elif self.isScroll():
            description.append(
                "accessibility information: scroll to see more options(very useful!)"
            )

        if len(self.resourceId.split("/")) > 1:
            description.append(f"resource_id {self.resourceId.split('/')[-1]}")
        if self.textRelevant:
            if self.text not in ["ON", "OFF"]:
                description.append(f"text: {self.text}")
            #    description.append(f"text: turned {self.text}")
            # else:

        description = ", ".join(description) if len(description) != 0 else ""

        return f"a View ({description})"

    def dumpAsWidget(self):
        description = []
        if self.contentDesc != "":
            description.append(f"content-desc: {self.contentDesc}")
        if self.resourceId != "":
            description.append(f"resource-id {self.resourceId}")
        if self.text != "":
            description.append(f"text: {self.text}")
        if "Button" in self.clazz:
            description.append(f"checked: {self.attrib['checked']}")
        description = ", ".join(description) if len(description) != 0 else ""

        return f"a View ({description})"

    def dumpAsDict(self) -> dict:
        return deepcopy(self.attrib)

    def __hash__(self):
        keys = [
            "actionTypes",
            "clazz",
            "resourceId",
            "contentDesc",
            "package",
        ] + ([] if "EditText" in self.clazz else ["text"])
        return hash(
            ", ".join([f"{key}: {self.__dict__[key]}" for key in keys])
        )

    def __eq__(self, other: "Widget"):
        if other is None:
            return False
        return all(
            self.__getattribute__(a) == other.__getattribute__(a)
            for a in ["resourceId", "contentDesc", "clazz"]
            + ([] if "EditText" in self.clazz else ["text"])
        )


class Event:
    widget: Widget
    action: str

    @staticmethod
    def back():
        return Event(None, "back")

    @staticmethod
    def ensureWidget(widget) -> Widget:
        if widget is None or type(widget) == Widget:
            return widget
        elif type(widget) == Element:
            widget = Widget(widget)
        else:
            raise NotImplementedError()

    def __init__(self, widget, action: str):
        widget = Event.ensureWidget(widget)

        if not (action == "back" or action in widget.actionTypes):
            print(
                "WARNING: action is not in the action type supported by the widget selected"
            )

        self.widget = widget
        self.action = action
        self.input = None

    def __eq__(self, other: "Event"):
        if (self.action == "back") ^ (other.action == "back"):
            return False
        elif self.action == "back" and other.action == "back":
            return True
        return self.widget == other.widget and self.action == other.action

    def __str__(self):
        widget = "back back"
        if self.widget:
            widget = self.widget.resourceId
            if "/" in widget:
                widget = widget.split("/")[1]
            if not widget.strip():
                widget = self.widget.text
            if self.input:
                widget += " input:" + self.input
        if len(widget.split()) < 1:
            widget += str(self.widget.pos)
        return self.action + " " + widget

    def dump(self, actionForm=False):
        if self.action == "back":
            return "back"
        elif self.action == "":
            return self.widget.dump()
        action = self.action
        if (
            self.action == "click"
            and self.widget.textRelevant
            and self.widget.text in ["ON", "OFF"]
        ):
            if self.widget.text == "ON":
                action = "turn off".upper()
            else:
                action = "turn on".upper()
        if actionForm:
            return f"{action} {self.widget.dump()}"
        else:
            return f"{self.widget.dump()} to {action}"

    def dumpAsDict(self) -> dict:
        ret = {}
        if self.widget is not None:
            ret = deepcopy(self.widget.attrib)
        ret["action"] = self.action
        return ret

    def act(self, controller: AndroidController):

        # print("acting action ", self.action, self.dumpAsDict())
        # TODO: maybe implement rule-based action
        if self.action in ("click", "long-click", "check"):
            pos = self.widget.pos
            click_pos = ((pos[2] + pos[0]) / 2, (pos[1] + pos[3]) / 2)
            controller.click(*click_pos)
        elif self.action == "back":
            controller.back()
        elif self.action == "swipe":
            pos = self.widget.pos
            fpos = ((pos[0] + pos[2]) / 2, (pos[3] * 7 + pos[1]) / 8)
            tpos = ((pos[2] + pos[0]) / 2, (pos[1] * 7 + pos[3]) / 8)
            controller.swipe(*(fpos + tpos))
        elif self.action == "text":
            pos = self.widget.pos
            click_pos = ((pos[2] + pos[0]) / 2, (pos[1] + pos[3]) / 2)
            controller.click(*click_pos)
            time.sleep(1)
            # print("afterclick")
            controller.input(self.input, clear=True)
        elif self.action == "":
            # default to clicking
            pos = self.widget.pos
            click_pos = ((pos[2] + pos[0]) / 2, (pos[1] + pos[3]) / 2)
            controller.click(*click_pos)
        else:
            raise NotImplementedError(self.action)
        time.sleep(4)

    @staticmethod
    def genAllEvents(widget, dull=False) -> List["Event"]:
        widget = Event.ensureWidget(widget)
        return (
            [Event(widget, a) for a in widget.actionTypes]
            if not dull or widget.actionTypes
            else [Event(widget, "")]
        )

    def withContext(self, hierarchy: RawHierarchy):
        return EventWithContext(self.widget, self.action, hierarchy)


def isVisible(node):
    return all(node.get(p) == "true" for p in ["focusable", "visible-to-user"])


def isInteractable(node):
    """
    Returns True if the node is interactable.
    """
    if node.tag != "node":
        return False
    return node.get("enabled") == "true" and (
        "true" in [node.get(p) for p in property_to_event]
        or (node.get("class") == "android.widget.EditText" and isVisible(node))
    )


class EventWithContext(Event):
    _hierarchy: RawHierarchy

    def __init__(self, widget: Widget, action: str, hierarchy: RawHierarchy):
        super().__init__(widget, action)
        self._hierarchy = hierarchy

    @staticmethod
    def getInteractPos(widget: Widget) -> tuple:
        pos = widget.pos
        return ((pos[2] + pos[0]) / 2, (pos[1] + pos[3]) / 2)

    def findActualElement(self, interact_pos) -> Element:
        return next(
            filter(
                lambda x: isInteractable(x)
                and posIn(interact_pos, parseBound(x.attrib["bounds"])),
                self._hierarchy._hierarchy.iter(),
            )
        )

    def __eq__(self, other: "EventWithContext"):
        # need to check here if actions are the same and the widget they're interacting with are actually the same
        if self.action != other.action:
            return False
        if self.action == "back" and other.action == "back":
            return True
        # print(self.widget.attrib, other.widget.attrib)
        if Widget(
            self.findActualElement(
                EventWithContext.getInteractPos(self.widget)
            )
        ) == Widget(
            self.findActualElement(
                EventWithContext.getInteractPos(other.widget)
            )
        ):
            return True
        return False


class EventSeq:
    sequence: List[Event]

    def __init__(self, _seq=None):
        if _seq is None:
            _seq = []
        self.sequence = deepcopy(_seq)

    def __getitem__(self, item):
        return self.sequence[item]

    def __iter__(self):
        return iter(self.sequence)

    def __len__(self):
        return len(self.sequence)

    def clear(self):
        self.sequence.clear()

    def append(self, event: Event):
        self.sequence.append(event)

    def dump(self, path):
        # build up the dumped list
        dump = [
            {"action": event.action, **event.widget.attrib}
            for event in self.sequence
        ]

        if path is None:
            return json.dumps(dump, indent=4)
        with open(path, "w") as f:
            json.dump(dump, f, indent=4)


class TestCase:
    _events: EventSeq
    _hierarchies: List[RawHierarchy]

    def __init__(self, events=EventSeq([]), hierarchies=None):
        if hierarchies is None:
            hierarchies = []
        self._events = EventSeq(events)
        self._hierarchies = []
        self._hierarchy_strings = []
        for hierarchy in hierarchies:
            if type(hierarchy) == RawHierarchy:
                self._hierarchies.append(hierarchy)
            else:
                self._hierarchies.append(RawHierarchy(hierarchy._hierarchy))

    def __len__(self):
        return len(self._events)

    @staticmethod
    def loadPart(folder: Path, status: str, bound: int, testCase: "TestCase"):
        with open(folder / f"{status}.json") as f:
            actions = json.load(f)
        # print(bound)
        for i in range(bound):
            action: dict = actions[i]
            act = action.pop("action")
            widget = Widget(action)
            testCase._events.append(Event(widget, act))
            # next read the hierarchy
            with open(folder / f"{status}{i}.xml") as f:
                # print(f"{status}{i}.xml")
                hierarchy_str = f.read()
                testCase._hierarchy_strings.append(hierarchy_str)
                testCase._hierarchies.append(
                    RawHierarchy(ET.fromstring(hierarchy_str))
                )

    @staticmethod
    def loadFromDisk(folder: Path, only_test=True):
        ret = TestCase()
        with open(folder / "index.json") as f:
            metaData = json.load(f)
        with open(folder / "init.xml") as f:
            ret._hierarchies.append(RawHierarchy(ET.parse(f).getroot()))
        TestCase.loadPart(folder, "body", metaData["body"], ret)
        if not only_test and "pre_oracle" in metaData:
            TestCase.loadPart(
                folder, "pre_oracle", metaData["pre_oracle"], ret
            )
        return ret

    def dump(self, path: Path):
        with open(path / "index.json", "w") as f:
            json.dump({"body": len(self._events)}, f)
        self._hierarchies.pop(0).dump(path / "init.xml")
        with open(path / "body.json", "w") as f:
            json.dump([e.dumpAsDict() for e in self._events], f)
        for idx, hierarchy in enumerate(self._hierarchies):
            hierarchy.dump(path / f"body{idx}.xml")

    def completionRate(expected: "TestCase", actual: "TestCase"):
        length = min(len(expected), len(actual))
        for i in range(length - 1):
            try:
                if expected._events[i].withContext(
                    expected._hierarchies[i + 1]
                ) != actual._events[i].withContext(actual._hierarchies[i + 1]):
                    return i / len(expected)
            except Exception as e:
                # print(e)
                return i / len(expected)
        if len(actual) < len(expected):
            return len(actual) / len(expected)
        return 1

    def looseCompletionRate(
        expected: "TestCase", actual: "TestCase", full: "TestCase"
    ):
        actual = full
        for i in range(len(expected) - 1, 0, -1):
            try:
                if expected._hierarchies[i] in actual._hierarchies[i:]:
                    return i / len(expected)
            except Exception as e:
                error_message = traceback.format_exc()
                # print(error_message)
                pass
        return 0

    def hitrate(expected: "TestCase", actual: "TestCase", full: "TestCase"):
        actual = full
        for i in range(len(expected) - 1, 0, -1):
            try:
                if expected._hierarchies[i] in actual._hierarchies:
                    return i / len(expected)
            except Exception as e:
                error_message = traceback.format_exc()
                # print(error_message)
                pass
        return 0

    def expectedLength(
        expected: "TestCase", actual: "TestCase", full: "TestCase"
    ):
        return len(expected._events)

    metrics = [completionRate, looseCompletionRate, expectedLength, hitrate]
