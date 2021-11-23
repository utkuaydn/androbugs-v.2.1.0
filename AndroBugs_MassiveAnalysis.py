from io import FileIO, TextIOWrapper
import traceback
import argparse
import multiprocessing
import os
import sys

ANALYZE_ENGINE_BUILD_DEFAULT = 1  # Analyze Engine(use only number)

def parseArgument():
    parser = argparse.ArgumentParser(
        description='AndroBugs Framework: Android APK Vulnerability Scanner - Massive Tool')
    parser.add_argument("-d", "--input_apk_dir", help="APK input directory to analyze", type=str, required=True)
    parser.add_argument("-b", "--analyze_engine_build", help="Analysis build number.", type=int, required=False, default=ANALYZE_ENGINE_BUILD_DEFAULT)
    parser.add_argument("-tag", "--analyze_tag", help="Analysis tag to uniquely distinguish this time of analysis.",
                        type=str, required=False, default=None)
    parser.add_argument("-o", "--report_output_dir", help="Analysis Report Output Directory.", type=str, required=True)
    parser.add_argument("-e", "--extra",
                        help="1)Do not check(default)  2)Check  security class names, method names and native methods",
                        type=int, required=False, default=1)
    parser.add_argument("-i", "--ignore_duplicated_scanning",
                        help="If you specify this argument, APKs with the same \"package_name\", \"analyze_engine_build\" and \"analyze_tag\" will not be analyzed again.",
                        action="store_true")
    parser.add_argument("-s", "--store_analysis_result_in_db",
                        help="Specify this argument if you want to store the analysis result in MongoDB. Please add this argument if you have MongoDB connection.",
                        action="store_true")
    parser.add_argument("-j", "--json", action="store_true", required=False)
    parser.add_argument("-t", "--text", action="store_true", required=False)
    parser.add_argument("-p", "--print", action="store_true", required=False)
    args = parser.parse_args()
    return args


def main():
    args = parseArgument()

    print()
    print("## AndroBugs Framework: Android APK Vulnerability Scanner - Massive Tool ##")
    print()

    if args.store_analysis_result_in_db:

        from pymongo import MongoClient
        from configparser import ConfigParser

        db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

        if not os.path.isfile(db_config_file):
            print(("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file))
            traceback.print_exc()

        configParser = ConfigParser()
        configParser.read(db_config_file)

        MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
        MongoDB_Port = configParser.getint('DB_Config', 'MongoDB_Port')
        MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')

        Collection_Analyze_Result = configParser.get('DB_Collections', 'Collection_Analyze_Result')

        client = MongoClient(MongoDB_Hostname, MongoDB_Port)
        db = client[MongoDB_Database]  # Name is case-sensitive
        collection_AppInfo = db[Collection_Analyze_Result]  # Name is case-sensitive

        print("[Notice] APK with the same \"package_name\", \"analyze_engine_build\" and \"analyze_tag\" will not be "
              "analyzed again.")
        print()

    input_dir = os.path.realpath(args.input_apk_dir)
    output_dir = os.path.realpath(args.report_output_dir)

    if (not os.path.isdir(input_dir)):
        print("APK input directory does not exist.")
        sys.exit()

    dir_names = os.listdir(input_dir)
    total_dir = len(dir_names)
    current_file = 0
    filenames = []

    print("CPU count: %d" % multiprocessing.cpu_count())

    for filename in dir_names:
        if filename.endswith(".apk"):
            current_file = current_file + 1

            if args.ignore_duplicated_scanning:  # check if already scanned
                package_name = filename[:-4]
                query_condition = {"analyze_mode": "massive",
                                   "package_name": package_name,
                                   "analyze_engine_build": args.analyze_engine_build,
                                   "analyze_tag": args.analyze_tag}

                if collection_AppInfo.find(query_condition):
                    print((" -> Package name [" + package_name + "] is already in DB. Ignore analyzing it."))
                    continue

            print(("Appending APK(" + str(current_file) + "/" + str(total_dir) + "): " + filename))
            filenames.append(filename)
    
    a = Analysis(input_dir, output_dir, args)

    print("Running parallel analysis")
    with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
        p.map(a.analyse, filenames)
    print("Parallel analysis complete!")
    os.remove(input_dir + "/scanned.txt")


class Analysis():
    def __init__(self, input_dir, output_dir, args):
        self._input_dir = input_dir
        self._output_dir = output_dir
        self._args = args

    def analyse(self, filename):
        try:
            with open(self._input_dir + "/scanned.txt", "r") as scanned:
                for line in scanned.readlines():
                    if filename == line.strip():
                        print(f"{filename} was scanned previously.")
                        return
        except IOError:
            pass
                
        main_cmd = "python3 androbugs.py"

        if self._args.store_analysis_result_in_db:
            if self._args.json and self._args.print and self._args.text:
                cmd = main_cmd + " -v -s -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -j -p -t"
            elif self._args.json and self._args.print:
                cmd = main_cmd + " -v -s -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -j -p"
            elif self._args.json and self._args.text:
                cmd = main_cmd + " -v -s -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -j -t"
            elif self._args.print and self._args.text:
                cmd = main_cmd + " -v -s -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -p -t"
            elif self._args.json:
                cmd = main_cmd + " -v -s -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -j"
            elif self._args.print:
                cmd = main_cmd + " -v -s -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -p"
            elif self._args.text:
                cmd = main_cmd + " -v -s -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -t"
        
        else:
            if self._args.json is False and self._args.text is False:
                cmd = main_cmd + " -v -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                            filename)) + "\" -o \"" + (self._output_dir) + \
                    "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag)
            elif self._args.json and self._args.print and self._args.text:
                cmd = main_cmd + " -v -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -j -p -t"
            elif self._args.json and self._args.print:
                cmd = main_cmd + " -v -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -j -p"
            elif self._args.json and self._args.text:
                cmd = main_cmd + " -v -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -j -t"
            elif self._args.print and self._args.text:
                cmd = main_cmd + " -v -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -p -t"
            elif self._args.json:
                cmd = main_cmd + " -v -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -j"
            elif self._args.print:
                cmd = main_cmd + " -v -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -p"
            elif self._args.text:
                cmd = main_cmd + " -v -e " + str(self._args.extra) + " -f \"" + (os.path.join(self._input_dir,
                                                                                        filename)) + "\" -o \"" + (self._output_dir) + \
                "\" -m massive -b " + str(self._args.analyze_engine_build) + " -tag " + str(self._args.analyze_tag) + " -t"
        try:
            p = os.popen(cmd)
            preprocessed = p.read()
            p.close()
            with open(self._input_dir + "/scanned.txt", "a+") as scanned:
                try:
                    scanned.write(filename + "\n")
                except IOError:
                    print(f"{filename} could not be written to scanned.txt")
        except KeyboardInterrupt:
            print("Stopped.")
        except Exception as err:
            print(err)


if __name__ == "__main__":
    main()
