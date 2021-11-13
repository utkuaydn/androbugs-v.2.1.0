import constants
from vector_base import VectorBase
from constants import *
from engines import *
import utils
import base64

class Vector(VectorBase):
    description = "Checks for which broadcasts the app listens to."
    tags = ["LISTEN_PACKAGE_ADDED", "LISTEN_PACKAGE_CHANGED", "LISTEN_PACKAGE_REPLACED", "LISTEN_PACKAGE_REMOVED"] # list of tags that are checked within this class

    def analyze(self) -> None:

        xml = self.apk.get_android_manifest_xml()
        receiver_list = utils.get_elements_by_tagname(xml, "receiver")

        for receiver in receiver_list:
            intent_filters = utils.get_elements_by_tagname(receiver, "intent-filter")
            for intent_filter in intent_filters:
                actions = utils.get_elements_by_tagname(intent_filter, "action")
                for action in actions:
                    action_name = action.attrib.get("{http://schemas.android.com/apk/res/android}name")
                    if action_name == "android.intent.action.PACKAGE_ADDED":
                        self.writer.startWriter("LISTEN_PACKAGE_ADDED", LEVEL_WARNING, 
                                                "App Listens for Added Applications",
                                                "This app is notified when an application is installed on the device.")
                    if action_name == "android.intent.action.PACKAGE_CHANGED":
                        self.writer.startWriter("LISTEN_PACKAGE_CHANGED", LEVEL_WARNING, 
                                                "App Listens for Changed Applications",
                                                "This app is notified when an application is changed on the device.")
                    if action_name == "android.intent.action.PACKAGE_REPLACED":
                        self.writer.startWriter("LISTEN_PACKAGE_REPLACED", LEVEL_WARNING, 
                                                "App Listens for Replaced Applications",
                                                "This app is notified when an application is replaced on the device.")
                    if action_name == "android.intent.action.PACKAGE_REMOVED":
                        self.writer.startWriter("LISTEN_PACKAGE_REMOVED", LEVEL_WARNING, 
                                                "App Listens for Removed Applications",
                                                "This app is notified when an application is removed on the device.")

        
        # obtain list of apps that are being checked whether they are installed from androidmanifest


        ## list of installed applications
        # all_methods = self.analysis.get_methods()
        # for method in all_methods:
        #     if method.name == "getInstalledApplications":
        #         calls = list(method.get_xref_from())
        #         for i in range(len(calls)):
        #             fields = list(calls[i][0].get_fields())
        #             for field in fields:
        #                 print("get field: ", field.get_field())
        #                 print("field name: ", field.name)
        #                 print("xref read: ", field.get_xref_read())
        #                 print("xref write: ", field.get_xref_write())