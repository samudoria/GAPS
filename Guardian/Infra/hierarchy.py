import sys
import xml.etree.ElementTree as ET
from Infra.infra import Widget, Event
from typing import List

from Infra.util import concatStrings, jsonToET

property_to_event = {
    "clickable": "click",
    #'long-clickable': 'longclick',
    "scrollable": "swipe",
    #'checkable': 'check'
}

ANDROID_SYSTEM_UI = "com.android.systemui"
NAVIGATION_BG = "android:id/navigationBarBackground"


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


def isSystemWidget(widget):
    return (
        widget.get("resource-id") == NAVIGATION_BG
        or widget.get("package") == ANDROID_SYSTEM_UI
    )


def ParseBound(bounds):
    left_top, right_bot = bounds.split("][")
    x1, y1 = left_top[1:].split(",")
    x2, y2 = right_bot[:-1].split(",")
    return list(map(lambda x: int(x), [x1, y1, x2, y2]))


def rewriteDescription(root):
    """
    Some of the info regarding clickable elements are in its child nodes.
    This function tries to find a child node with text, or does not set the text otherwise.
    """
    for elem in filter(lambda x: x.get("clickable") == "true", root.iter()):
        elem: ET.Element
        if elem.get("text", "").strip() == "":
            try:
                elem.set(
                    "text",
                    next(
                        filter(
                            lambda x: x.get("text", "").strip() != "",
                            elem.iter(),
                        )
                    ).get("text"),
                )
            except StopIteration:
                pass


def setActualClickable(root):
    """
    Some of the elements are 'clickable wrappers' of the actual elements that are clickable from user's perspective.
    This function finds such wrappers and pass down the clickable attribute to the RelativeLayout children.
    Also passes down the resource id and content description.
    """
    list_group = ["android.widget.RelativeLayout", "android.view.ViewGroup"]
    for elem in filter(lambda x: x.get("clickable") == "true", root.iter()):
        childs = list(elem.findall("node"))
        if sum(child.get("class") in list_group for child in childs) > 2:
            elem.set("clickable", "false")
            for child in filter(
                lambda x: x.get("class") in list_group, childs
            ):
                child.set("clickable", "true")
                # child.set("needtext", "true")
                child.attrib["resource-id"] = concatStrings(
                    [elem.get("resource-id"), child.get("resource-id")]
                )
                child.attrib["content-desc"] = concatStrings(
                    [elem.get("content-desc"), child.get("content-desc")],
                    " and ",
                )


def setNeedText(root: ET.Element, app_name):
    if app_name is None:
        for node in root.iter():
            node.set("needtext", "true")
        return

    text_keywords = []
    for node in root.iter():
        if node.get("text") in text_keywords:
            node.set("needtext", "true")

    # parent_map = {c: p for p in root.iter() for c in p}
    # for node, parent in parent_map.items():
    #    # TODO: check if is list
    #    if node.get('clickable') == "true" and parent.get('class') in ["android.widget.LinearLayout"]:
    #        node.set('needtext', 'true')
    #    elif 'EditText' in node.get('class'):
    #        node.set('needtext', 'true')


def parseUIHierarchy(
    root, _filter=isInteractable, _reformClickable=True, app_name=None
) -> list:
    """
    Parses the UI hierarchy XML string and returns a list of dictionaries containing the information about each view.
    Return a list of widgets (each widgets is a dictionary) [{widget_id:xxx, group_id:xxx, pos:[x0,y0,x1,y1],event_type:['click','longclick','swipe','check'],class:xxx,resource-id:xxx,content-desc:xxx}].
    """

    if _reformClickable:
        # passes down the clickable attribute to the actual elements
        setActualClickable(root)
        # rewrite the resource-id and content-desc of each interactable widget
        rewriteDescription(root)
        # set the needtexts
        setNeedText(root, app_name)

    ret = [Widget(elem) for elem in root.iter() if _filter(elem)]
    for widget in ret:
        if widget.package == "com.android.systemui":
            ret.remove(widget)
            continue
        widget.fixTextEdit()
    return ret


def strip_empty_segmentations(origin_id: str):
    path_ids = origin_id.split(";")
    remained = []
    for path_id in path_ids:
        if path_id == "#":
            continue
        if path_id == "ViewGroup#":
            continue
        remained.append(path_id)
    return ";".join(remained)


class Hierarchy:
    _events: List[Event]
    _widgets: List[Widget]
    _hierarchy: ET.Element

    def __iter__(self):
        return iter(self._widgets)

    def __getitem__(self, item):
        return self._widgets[item]

    def getEvents(self) -> List[Event]:
        raise NotImplementedError()

    def __eq__(self, other):
        raise NotImplementedError()


class TotalVisibleHierarchy(Hierarchy):
    def __init__(self, pkg, raw=None, backup=None):
        self._hierarchy = backup
        if type(raw) is str:
            raw = ET.fromstring(raw)
        self._widgets = [
            w
            for w in parseUIHierarchy(
                raw, lambda x: x.get("visible-to-user") == "true", False
            )
            if w.package == pkg
        ]

    def getEvents(self) -> List[Event]:
        if self._events is None:
            self._events = sum(
                [
                    Event.genAllEvents(widget, dull=True)
                    for widget in self._widgets
                ],
                [],
            )
            # self._events.append(Event.back())
        return self._events


class VisibleHierarchy(Hierarchy):
    def __init__(self, raw=None, backup=None):
        self._hierarchy = backup
        if type(raw) is str:
            raw = ET.fromstring(raw)
        self._widgets = parseUIHierarchy(raw, isVisible, False)
        if type(raw) is str:
            raw = ET.fromstring(raw)

        self._events = None

    def getEvents(self) -> List[Event]:
        if self._events is None:
            self._events = sum(
                [
                    Event.genAllEvents(widget, dull=True)
                    for widget in self._widgets
                ],
                [],
            )
            self._events.append(Event.back())
        return self._events


class SemanticHierarchy(Hierarchy):

    def __init__(self, pkg_name, app_name, _rawHierarchy=None, backup=None):
        self._hierarchy = backup
        self._events = None
        self.pkg_name = pkg_name
        self.app_name = app_name
        self.positions = dict()
        self.assigned = False
        if _rawHierarchy is None:
            self._widgets = []
            return
        if type(_rawHierarchy) is str:
            try:
                _rawHierarchy = ET.fromstring(_rawHierarchy)
            except:
                self._widgets = []
                return
        """
        self._widgets = list(
            filter(
                lambda x: x.package
                in [self.pkg_name, "com.android.packageinstaller"],
                parseUIHierarchy(_rawHierarchy),
            )
        )
        """
        self._widgets = list(
            filter(
                lambda x: ".NexusLauncherActivity" not in x.package,
                parseUIHierarchy(_rawHierarchy),
            )
        )
        # self._widgets = list(parseUIHierarchy(_rawHierarchy))

    def getEvents(self) -> List[Event]:
        if self._events is None:
            self._events = sum(
                [Event.genAllEvents(widget) for widget in self._widgets], []
            )
            # self._events.append(Event.back())
        return self._events

    def HierarchyFilter(self, root: ET.Element):
        widgets = parseUIHierarchy(root)  # app_name=self.app_name)
        for widget in widgets:
            if "EditText" in widget["class"]:
                widget["event_type"].append("text")
                if "click" in widget["event_type"]:
                    widget["event_type"].remove("click")
        return widgets

    def parse_tabwidgets(self):
        tabs = []
        for W in self.linear:
            if "TabWidget" in W["widget_id"]:
                tabs.append(W)
        return tabs


class TextMergeHierarchy(Hierarchy):
    def __init__(self, pkg, raw=None, backup=None):
        self._hierarchy = backup
        if type(raw) is str:
            raw = ET.fromstring(raw)
        self._widgets = [
            w
            for w in parseUIHierarchy(
                raw, lambda x: x.get("package") == pkg, False
            )
        ]
        self._events = None

    def getEvents(self) -> List[Event]:
        if self._events is None:
            self._events = sum(
                [
                    Event.genAllEvents(widget, dull=True)
                    for widget in self._widgets
                ],
                [],
            )
            self._events.append(Event.back())
        return self._events


if __name__ == "__main__":

    def buildHierarchyTree(xml_file):
        if xml_file.endswith(".xml"):
            tree = ET.parse(xml_file)
            return tree.getroot()
        else:
            with open(xml_file) as f:
                return jsonToET(f.read())

    root = buildHierarchyTree("dev/simplelarmclock.ml")
    h = TextMergeHierarchy("com.better.alarm", root)
    # setActualClickable(root)
    # rewriteDescription(root)
    # # drawXmlTree(root)

    # tree = ET.ElementTree()
    # tree._setroot(root)
    # tree.write("output.xml")
    # print(list(SemanticHierarchy('', root)))
