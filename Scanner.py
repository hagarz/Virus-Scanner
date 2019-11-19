__author__ = 'Hagar Zemach'

import os, platform, sys
import VirusTotal
if platform.platform()[:10] != "Windows-10":
    raise SystemError('Windows 10 compatible')
if sys.version_info[0] < 3:
    raise Exception("Must be using Python 3")


def load_ext_list():
    """ creating a list of executable Windows file extensions"""
    execution_extensions = []
    with open("high_risk_file_ext.txt", 'r') as file:
        for row in file:
            row = [x.strip() for x in row.split('\t')]
            if "windows" in str.lower(row[-1]):
                execution_extensions.append(row[0])
    file.close()

    with open("more_exec_file_exte.txt", 'r') as f:
        for row in f:
            row = [x.strip() for x in row.split('\t')]
            execution_extensions.append(row[0])
    f.close()

    return execution_extensions


class UsersAndFolders(object):
    """
    creating a list of folder paths to be scanned
    """
    def __init__(self,path_list):

        self.user_list = []
        self.path_list = []
        self.path_list = path_list

        # initialize list of users:
        self.user_list += [user for user in os.listdir(r'C:\Users')]

        # add user-specific paths to list:
        for user in self.user_list:
            self.path_list.extend([
                r'C:\Users\\' + str(user) + '\AppData\Local',
                r'C:\Users\\' + str(user) + '\AppData\Roaming',
                r'C:\Users\\' + str(user) + '\Desktop',
                r'C:\Users\\' + str(user) + '\Downloads'
            ])

    def update_users(self):
        """get all user names and return them in a list os strings"""
        self.user_list += [user for user in os.listdir(r'C:\Users')]

    def get_users(self):
        return self.user_list

    def update_paths(self):
        for user in self.user_list:
            self.path_list.append(
                r'C:\Users\\' + str(user) + '\AppData\Local',
                r'C:\Users\\' + str(user) + '\AppData\Roaming',
                r'C:\Users\\' + str(user) + '\Desktop',
                r'C:\Users\\' + str(user) + '\Downloads'
            )

    def get_paths(self):
        return self.path_list


class Scan(object):
    """
    This is the controller.
    search executable files in folders, then send to virus total to be scanned and fetch report
    """
    def __init__(self,paths_list):
        self.ext_list = load_ext_list()  # loading list of executables extensions
        self.paths = paths_list  # initializing list of 'suspicious' folders
        self.tb_scanned = []

    def start_scan(self):
        self.paths = UsersAndFolders(self.paths).get_paths()  # getting list of paths to 'suspicious' folders
        self.tb_scanned = search_files(self.paths, self.ext_list)  # calling a method to scan the computer

        # send files to VirusTotal for scanning
        vt = VirusTotal.VirusTotal()
        vt.vt_mng(self.tb_scanned[500:700])


def search_files(paths, ext_list):
    """
    iterate over files in listed folders and subfolders and gather executable file in these locations
    :param paths:  a list containing paths to folders which may contain infected files
    :param ext_list: lisr of executable extensions
    :return: a list of file names
    """
    tb_scanned = []
    for path in paths:
        for (dirpath, dirnames, filenames) in os.walk(path):
            for file in filenames:
                for ext in ext_list:
                    l_ext = ext.lower()
                    l_file = file.lower()
                    if l_file.endswith("." + l_ext):
                        tb_scanned.append(os.path.join(dirpath, file))
                        break

    print(f"sending {len(tb_scanned)} to be scanned ")

    return tb_scanned



if __name__ == '__main__':
    paths_list = [
        r"C:\Windows\Temp", r"C:\Temp",r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    ]
    Scan(paths_list).start_scan()





