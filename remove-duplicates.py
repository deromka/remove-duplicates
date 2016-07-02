#!/usr/bin/env python

# install: sudo pip install futures
import logging
import exifread
import os
import shutil
import hashlib
import sys
import time
import datetime
import ntpath
import glob
import concurrent.futures
import multiprocessing



logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.WARNING)
# create logger
logger = logging.getLogger('remove-duplicates')
logger.setLevel(logging.INFO)

# Thread Pool
pool = None

def getPoolSize():
    return multiprocessing.cpu_count()*2

def createPool():
    global pool
    # Make the Pool of workers
    psize = getPoolSize()
    logger.info("Thread Pool size {}".format(psize))
    pool = concurrent.futures.ThreadPoolExecutor(psize)


class InputArguments(object):

    # create logger
    logger = logging.getLogger('InputArguments')
    logger.setLevel(logging.INFO)

    def __init__(self, argv):
        if len(argv) < 3:
            print("Usage: remove-duplicates.py <source dir to hash> <remove from destination directory>")
            exit(1)

        self.dirname = argv[1]
        self.destdirname = argv[2]

        logger.info("Using source directory (recursive): {}".format(self.dirname))
        logger.info("Using destination directory: {}".format(self.destdirname))

        if not self.dirname:
            print "source directory cannot be empty!"
            exit(1)

        if not self.destdirname:
            print "destination directory cannot be empty!"
            exit(1)

        if not os.path.isdir(self.dirname):
            print("source directory {} does not exist!".format(self.dirname))
            exit(1)

        if not os.path.isdir(self.destdirname):
            self.logger.info ("destination directory {} does not exist, creating it...".format(self.destdirname))
            print ("Created dir {}".format(self.destdirname))
            os.makedirs(self.destdirname)
    def abs_src_path(self, filename):
        return self.dirname + os.path.sep + filename

    def abs_dest_path(self, filename):
        return self.destdirname + os.path.sep + filename


class Stats(object):
    # create logger
    logger = logging.getLogger('Stats')
    logger.setLevel(logging.WARNING)

    def __init__(self):
        self.stats = {}
        self.total = {}

    def report(self, key, name):
        dirStats = self.stats.get(key, {})
        curr = dirStats.get(name, 0)
        dirStats[name]=curr + 1
        self.stats[key]=dirStats
        curtype = self.total.get(name, 0)
        self.total[name]=curtype + 1

    def __repr__(self):
        str = []
        if self.stats:
            str.append("\nSummary: \n")
            for cdir, cdirStats in self.stats.items():
                str.append("\nDirectory {}".format(cdir))
                for op, count in cdirStats.items():
                    str.append("\t{} files {}".format(count, op))

            for op, count in self.total.items():
                str.append("\n\nTotal {} files {}".format(count, op))
        else:
            str.append("\nNo stats were updated.")

        out_str = ''.join(str)
        return out_str



def hash_file(args, stats, file, fileshash):
    src_file_path = os.path.abspath(file)
    logger.debug("Hashing file {} ...".format(src_file_path))

    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file)


    if os.path.isfile(src_file_path):
        # files with the same name exist
        # check their hashes, whether they are the same
        currfileHash = md5(src_file_path)
        stats.report(file, 'hashed')
        logger.debug("file {} hashed {}".format(src_file_path, currfileHash))
        item = fileshash.get(currfileHash, {})
        item['source_path']=src_file_path
        fileshash[currfileHash]=item


def check_file_hash(args, stats, file, fileshash, movedir):
    src_file_path = os.path.abspath(file)
    logger.debug("Checking file hash {} ...".format(src_file_path))

    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file)


    if os.path.isfile(src_file_path):
        # files with the same name exist
        # check their hashes, whether they are the same
        currfileHash = md5(src_file_path)
        stats.report(file, 'checked')
        item = fileshash.get(currfileHash)
        if not item is None:
            orig_file = item.get('source_path')
            if not (orig_file is None) and (src_file_path != orig_file):
                logger.info("found duplicate file {} to {}".format(src_file_path, orig_file))
                dup_paths = item.get('duplicate_paths', set())
                dup_paths.add(src_file_path)
                shutil.move(src_file_path, movedir)
                logger.debug("file {} moved to {}".format(src_file_path, movedir))
                stats.report(src_file_path, 'moved')


def hash_dir(args, stats, dir, fileshash):
    abs_dir = os.path.abspath(dir)
    start = time.time()
    logger.info("Processing folder {} ...".format(abs_dir))
    for root, subdirs, files in os.walk(abs_dir):
        logger.debug(subdirs)
        logger.debug(files)

        for subdir in subdirs:
            getPool().submit(hash_dir(args, stats, os.path.join(root, subdir), fileshash))

        for f in files:
            file_path = os.path.join(root, f)
            hash_file(args, stats, file_path, fileshash)

    end = time.time()
    tookSec = end - start
    logger.info("Done with folder {} ({} sec).\n".format(abs_dir, tookSec))

def check_dir_hash(args, stats, dir, fileshash, movedir):
    try:
        abs_dir = os.path.abspath(dir)
        start = time.time()
        logger.info("Processing folder {} ...".format(abs_dir))
        for root, subdirs, files in os.walk(abs_dir):
            logger.debug(subdirs)
            logger.debug(files)

            for subdir in subdirs:
                getPool().submit(check_dir_hash(args, stats, os.path.join(root, subdir), fileshash, movedir))

            for f in files:
                file_path = os.path.join(root, f)
                check_file_hash(args, stats, file_path, fileshash, movedir)

        end = time.time()
        tookSec = end - start
        logger.info("Done with folder {} ({} sec).\n".format(abs_dir, tookSec))
    except:
        print('%s: %s' % (dir, traceback.format_exc()))

def removeEmptyFolders(path, removeRoot=True):
    'Function to remove empty folders'
    if not os.path.isdir(path):
        return

    # remove empty subfolders
    files = os.listdir(path)
    if len(files):
        for f in files:
            fullpath = os.path.join(path, f)
            if os.path.isdir(fullpath):
                removeEmptyFolders(fullpath)

    # if folder empty, delete it
    files = os.listdir(path)
    if len(files) == 0 and removeRoot:
        logger.info("Removing empty folder: {}".format(path))
        os.rmdir(path)


def getPool():
    return pool


def main(argv):


    args = InputArguments(argv)


    stats = Stats()
    fileshash = {}


    movedir = '~/tmp/duplicates/'
    if not os.path.isdir(movedir):
        os.makedirs(movedir)

    abs_src_dir = os.path.abspath(args.dirname)
    abs_dest_dir = os.path.abspath(args.destdirname)

    createPool()

    logger.info("Hashing folder {} ...".format(abs_src_dir))
    hash_dir(args, stats, abs_src_dir, fileshash)

    getPool().shutdown()
    createPool()

    logger.info(stats)

    logger.info("Checking hashes in folder {} ...".format(abs_dest_dir))
    check_dir_hash(args, stats, abs_dest_dir, fileshash, movedir)

    logger.info(stats)

    getPool().shutdown()





def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


if __name__ == "__main__":
    main(sys.argv)