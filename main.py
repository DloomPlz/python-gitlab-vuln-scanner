
# Get Gitlab search results from a page.

# Doc gitlab : https://docs.gitlab.com/ee/api/search.html
# Doc lib gitlab for search : https://python-gitlab.readthedocs.io/en/stable/install.html
import sys
import argparse
import os
from local_scan import local_scan
from pprint import pprint


def main():

    if args.local:
        if not os.path.exists(args.local):
            sys.exit("a local path needs to be set")
        print("Launching local scan...")
        local_scan(args.local)        

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get potential security issues in a gitlab repository')
    parser.add_argument('-l', '--local', help="path to repository")
    args = parser.parse_args()
    global CONSOLE_ARGUMENTS
    CONSOLE_ARGUMENTS = args
    main()
   
    
