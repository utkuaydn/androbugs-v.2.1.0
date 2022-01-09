import constants
from vector_base import VectorBase
from constants import *
from engines import *
import utils
import base64

class Vector(VectorBase):
    description = "Checks for package listeners and queries performed by the app."
    tags = ["LISTEN_PACKAGE_ADDED_MANIFEST", "LISTEN_PACKAGE_CHANGED_MANIFEST", "LISTEN_PACKAGE_REPLACED_MANIFEST", "LISTEN_PACKAGE_REMOVED_MANIFEST", "LISTEN_PACKAGE_ADDED_DYNAMIC", "LISTEN_PACKAGE_CHANGED_DYNAMIC", 
            "LISTEN_PACKAGE_REPLACED_DYNAMIC", "LISTEN_PACKAGE_REMOVED_DYNAMIC", "QUERY_PERMISSION", "QUERY_OF_INTENT", "QUERY_OF_PACKAGE", "QUERY_WITHOUT_PERMISSION", "QUERY_OF_UNKNOWN_PACKAGES"] # list of tags that are checked within this class

    def analyze(self) -> None:
        xml = self.apk.get_android_manifest_xml()
        receiver_list = utils.get_elements_by_tagname(xml, "receiver")
        for receiver in receiver_list:
            intent_filters = utils.get_elements_by_tagname(receiver, "intent-filter")
            for intent_filter in intent_filters:
                actions = utils.get_elements_by_tagname(intent_filter, "action")
                for action in actions:
                    action_name = action.attrib.get("{http://schemas.android.com/apk/res/android}name")
                    if action_name == "android.intent.action.PACKAGE_ADDED" or action_name == "android.intent.action.PACKAGE_INSTALL":
                        self.writer.startWriter("LISTEN_PACKAGE_ADDED_MANIFEST", LEVEL_WARNING, 
                                                "App Listens for Added Applications",
                                                "This app is notified when an application is installed on the device. This broadcast receiver is declared in the manifest file.")
                    if action_name == "android.intent.action.PACKAGE_CHANGED":
                        self.writer.startWriter("LISTEN_PACKAGE_CHANGED_MANIFEST", LEVEL_WARNING, 
                                                "App Listens for Changed Applications",
                                                "This app is notified when an application is changed on the device. This broadcast receiver is declared in the manifest file.")
                    if action_name == "android.intent.action.PACKAGE_REPLACED":
                        self.writer.startWriter("LISTEN_PACKAGE_REPLACED_MANIFEST", LEVEL_WARNING, 
                                                "App Listens for Replaced Applications",
                                                "This app is notified when an application is replaced on the device. This broadcast receiver is declared in the manifest file.")
                    if action_name == "android.intent.action.PACKAGE_REMOVED" or action_name == "android.intent.action.PACKAGE_FULLY_REMOVED":
                        self.writer.startWriter("LISTEN_PACKAGE_REMOVED_MANIFEST", LEVEL_WARNING, 
                                                "App Listens for Removed Applications",
                                                "This app is notified when an application is removed on the device. This broadcast receiver is declared in the manifest file.")

        all_strings = self.analysis.get_strings()
        for string in all_strings:
            string_value = string.get_value()
            if string_value == "android.intent.action.PACKAGE_ADDED" or string_value == "android.intent.action.PACKAGE_INSTALL":
                calls = list(string.get_xref_from())
                for i in range(len(calls)):
                    call = calls[i][1].get_name()
                    if call == "IntentFilter" or call == "getIntExtra" or call == "addAction" or call == "onReceive":
                        self.writer.startWriter("LISTEN_PACKAGE_ADDED_DYNAMIC", LEVEL_WARNING, 
                                                "App Listens for Added Applications",
                                                "This app is notified when an application is installed on the device. This broadcast receiver is declared dynamically in the source code.")

            if string_value == "android.intent.action.PACKAGE_CHANGED":
                calls = list(string.get_xref_from())
                for i in range(len(calls)):
                    call = calls[i][1].get_name()
                    if call == "IntentFilter" or call == "getIntExtra" or call == "addAction" or call == "onReceive":
                        self.writer.startWriter("LISTEN_PACKAGE_CHANGED_DYNAMIC", LEVEL_WARNING, 
                                                "App Listens for Changed Applications",
                                                "This app is notified when an application is changed on the device. This broadcast receiver is declared dynamically in the source code.")

            if string_value == "android.intent.action.PACKAGE_REPLACED":
                calls = list(string.get_xref_from())
                for i in range(len(calls)):
                    call = calls[i][1].get_name()
                    if call == "IntentFilter" or call == "getIntExtra" or call == "addAction" or call == "onReceive":
                        self.writer.startWriter("LISTEN_PACKAGE_REPLACED_DYNAMIC", LEVEL_WARNING, 
                                                "App Listens for Replaced Applications",
                                                "This app is notified when an application is replaced on the device. This broadcast receiver is declared dynamically in the source code.")

            if string_value == "android.intent.action.PACKAGE_FULLY_REMOVED" or string_value == "android.intent.action.PACKAGE_REMOVED":
                calls = list(string.get_xref_from())
                for i in range(len(calls)):
                    call = calls[i][1].get_name()
                    if call == "IntentFilter" or call == "getIntExtra" or call == "addAction" or call == "onReceive":
                        self.writer.startWriter("LISTEN_PACKAGE_REMOVED_DYNAMIC", LEVEL_WARNING, 
                                                "App Listens for Removed Applications",
                                                "This app is notified when an application is removed on the device. This broadcast receiver is declared dynamically in the source code.")

        all_method_class_objects = self.analysis.get_methods()
        all_methods = [object.name for object in all_method_class_objects]
        all_permissions = self.apk.get_permissions()
        if "queryIntentActivities" in all_methods or "getInstalledApplications" in all_methods or "getPackageInfo" in all_methods or "getInstalledPackages" in all_methods:
            if self.int_target_sdk >= 30 or self.int_min_sdk >= 30:
                query_list = utils.get_elements_by_tagname(xml, "queries")
                queried_packages = []
                queried_intents = []
                for query in query_list:
                    # queries for specific packages
                    package_list = utils.get_elements_by_tagname(query, "package")
                    for package in package_list:
                        package_name = package.attrib.get("{http://schemas.android.com/apk/res/android}name")
                        queried_packages.append(package_name)

                    # queries using intent filter
                    intent_list = utils.get_elements_by_tagname(query, "intent")
                    for intent in intent_list:
                        action_name = utils.get_elements_by_tagname(intent, "action")[0].attrib.get("{http://schemas.android.com/apk/res/android}name")
                        data = utils.get_elements_by_tagname(intent, "data")
                        if data: 
                            try:             data_name = data[0].attrib.get("{http://schemas.android.com/apk/res/android}mimeType") 
                            except KeyError: data_name = None
                        else:                data_name = None
                        queried_intents.append((action_name, data_name))

                if "android.permission.QUERY_ALL_PACKAGES" in all_permissions:
                    self.writer.startWriter("QUERY_PERMISSION", LEVEL_CRITICAL, 
                                                    "App Has Permission to Query All Packages",
                                                    "This app has the permission QUERY_ALL_PACKAGES declared in it's AndroidManifest. Caution is advised.")

                if queried_intents:
                    self.writer.startWriter("QUERY_OF_INTENT", LEVEL_WARNING, 
                                                    "App Queries Application Intent(s)",
                                                    "This app queries the device and knows about the applications that use the below intent and (un)detected data type. Caution is advised.")
                    for (intent_name, data_name) in queried_intents:
                        if data_name == None:
                            self.writer.write(intent_name)
                        else:
                            self.writer.write(intent_name + " using the data type " + data_name)

                if queried_packages:
                    self.writer.startWriter("QUERY_OF_PACKAGE", LEVEL_WARNING, 
                                                    "App Queries Installed Application(s)",
                                                    "This app queries the device and knows if the applications below are installed. Caution is advised.")
                    for package in queried_packages:
                        self.writer.write(package)
                else:
                    self.writer.startWriter("QUERY_WITHOUT_PERMISSION", LEVEL_WARNING, 
                                                    "App Has No Permission to Query Installed Application(s)",
                                                    "This app tries to query the device for installed applications without having the permission. The app might not behave correctly.")
                
            else:
                self.writer.startWriter("QUERY_OF_UNKNOWN_PACKAGES", LEVEL_CRITICAL, 
                                                    "App Queries Installed Application(s)",
                                                    "This app queries the device and knows about the applications that are installed. Cannot tell which applications because SDK version is below 30. Caution is advised.")