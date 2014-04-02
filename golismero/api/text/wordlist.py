#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Wordlist API.
"""

__license__ = """
GoLismero 2.0 - The web knife - Copyright (C) 2011-2014

Golismero project site: https://github.com/golismero
Golismero project mail: contact@golismero-project.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

__all__ = ["WordListLoader", "WordlistNotFound"]

import bisect
import re
import copy

from os import walk
from abc import ABCMeta, abstractproperty
from golismero.api.localfile import LocalFile
from os.path import join, sep, abspath, exists, isfile

from .matching_analyzer import get_diff_ratio
from ...common import Singleton, get_wordlists_folder


#------------------------------------------------------------------------------
class WordlistNotFound(Exception):
    """Exception when wordlist not found"""


#------------------------------------------------------------------------------
class _WordListLoader(Singleton):
    """
    Wordlist API.
    """

    #--------------------------------------------------------------------------
    def __init__(self):

        # Store
        self.__store = {}  # Pair with: (name, path)

        # Initial load
        self.__load_wordlists(get_wordlists_folder())

    #--------------------------------------------------------------------------
    # Private methods
    #--------------------------------------------------------------------------
    def __get_wordlist_descriptor(self, wordlist):
        """
        Looking for the world list in this order:
        1 - In the internal database and.
        2 - Looking in the plugin directory
        3 - Looking the wordlist in the file system.

        If Wordlist not found, raise WordlistNotFound exception.

        :param wordlist: wordlist name
        :type wordlist: basestring

        :return: a file descriptor.
        :rtype: open()

        :raises: WordlistNotFound, TypeError, ValueError
        """
        if not isinstance(wordlist, basestring):
            raise TypeError("Expected 'str' got '%s'." % type(wordlist))

        # For avoid user errors, library accept also, wordlists starting as:
        # wordlist/....
        if wordlist.startswith("wordlist"):
            wordlist = "/".join(wordlist.split("/")[1:])

        if not wordlist:
            raise ValueError("Wordlist name can't be an empty value")

        try:
            return open(self.__store[wordlist], "rU")
        except KeyError:  # Wordlist is not in the internal database

            # Can open from plugin wordlists?
            internal = True
            try:
                if LocalFile.exists(wordlist):
                    if not LocalFile.isfile(wordlist):
                        internal = False

                    return LocalFile.open(wordlist, "rU")
                else:
                    internal = False
            except ValueError:
                internal = False

            if not internal:
                # Looking the wordlist in the file system, assuming that the
                # wordlist name is an absolute path.
                if exists(wordlist):
                    if not isfile(wordlist):
                        raise WordlistNotFound("Wordlist '%s' is not a file." % wordlist)

                    return open(wordlist, "rU")
                else:
                    raise WordlistNotFound("Wordlist file '%s' does not exist." % wordlist)

    #--------------------------------------------------------------------------
    def __load_wordlists(self, current_dir):
        """
        Find and load wordlists from the specified directory.

        .. warning: Private method, do not call!

        :param current_dir: Directory to look for wordlists.
        :type current_dir: str

        :raises: TypeError, ValueError
        """
        if not isinstance(current_dir, basestring):
            raise TypeError("Expected basestring, got '%s' instead" % type(current_dir))

        # Make sure the directory name is absolute and ends with a slash.
        current_dir = abspath(current_dir)
        if not current_dir.endswith(sep):
            current_dir += sep

        if not exists(current_dir):
            raise ValueError("Path directory for wordlist '%s' not exits" % current_dir)

        # Iterate the directory recursively.
        for (dirpath, _, filenames) in walk(current_dir):

            # Make sure the directory name is absolute.
            dirpath = abspath(dirpath)

            # Look for text files, skipping README files and disabled lists.
            for fname in filenames:
                if not fname.startswith("_") and fname.lower() != "readme.txt":

                    # Map the relative filename to the absolute filename,
                    # replacing \ for / on Windows.
                    target = join(dirpath, fname)
                    key = target[len(current_dir):]
                    if sep != "/":
                        key = key.replace(sep, "/")
                    self.__store[key] = target


    #--------------------------------------------------------------------------
    # Property
    #--------------------------------------------------------------------------
    @property
    def all_wordlists(self):
        """
        :returns: Names of all the wordlists.
        :rtype: list
        """
        return self.__store.keys()

    #--------------------------------------------------------------------------
    # Public methods
    #--------------------------------------------------------------------------
    def get_wordlist_as_raw(self, wordlist_name):
        """
        Get a wordlist line by line, in raw format.

        >>> values = ["hello", "world", "  this has spaces  ", "# A comment"]
        >>> open("my_wordlist.txt", "w").writelines(values)
        >>> w = WordListLoader.get_wordlist_as_raw("my_wordlist.txt")
        >>> for line in w:
            print line,
        hello
        world
          this has spaces
        # A comment


        :param wordlist_name: Name of the requested wordlist.
        :type wordlist_name: basestring

        :returns: Iterator for the selected wordlist.
        :rtype: iter(str)

        :raises: TypeError, ValueError, WordlistNotFound
        """
        if not isinstance(wordlist_name, basestring):
            raise TypeError("Expected basestring, got '%s' instead" % type(wordlist_name))
        if not wordlist_name:
            ValueError("Expected wordlist name, got None instead")

        fixed_wordlist = self.__get_wordlist_descriptor(wordlist_name)

        try:
            return _simple_iterator(fixed_wordlist)
        except IOError, e:
            raise WordlistNotFound("Error opening wordlist. Error: %s " % str(e))

    #--------------------------------------------------------------------------
    def get_wordlist_as_dict(self, wordlist_name, separator=";", smart_load=False):
        """
        Get a wordlist as a dict, with some search operations.

        Load a wordlist file, with their lines splited by some char, an load left str as a key, and right as a value.

        >>> values = ["hello", "world", "  this has spaces  ", "# A comment"]
        >>> open("my_wordlist.txt", "w").writelines(values)
        >>> w = WordListLoader.get_wordlist_as_l("my_wordlist.txt")
        >>> for line in w:
            print line,
        hello
        world
        this has spaces
        A comment
        >>>


        :param wordlist_name: Wordlist name.
        :type wordlist_name: str

        :param separator: value used to split the lines
        :type separator: str

        :param smart_load: Indicates if the wordlist must detect if the line has values that can be converted in a list.
        :type smart_load: bool

        :returns: Advanced wordlist object.
        :rtype: WDict
        """

        return WDict(self.__get_wordlist_descriptor(wordlist_name), smart_load, separator)

    #--------------------------------------------------------------------------
    def get_wordlist_as_list(self, wordlist_name):
        """
        Get a wordlist as a list, with some search operations.

        Also apply these filter to each line:
        - Filter commented lines (starting with '#')
        - Remove end chars: line return '\n', tabs '\t' or carry line.
        - Remove start and end spaces.

        >>> values = ["hello", "world", "  this has spaces  ", "# A comment", "word"]
        >>> open("my_wordlist.txt", "w").writelines(values)
        >>> w = WordListLoader.get_wordlist_as_list("my_wordlist.txt")
        >>> for line in w:
            print line,
        hello
        world
        this has spaces
        A comment
        >>> w.se

        :param wordlist_name: Wordlist name.
        :type wordlist_name: str

        :returns: WList.
        :rtype: WList
        """

        return WList(self.__get_wordlist_descriptor(wordlist_name))


#----------------------------------------------------------------------
def _simple_iterator(wordlist_handler):
    """
    Simple iterator function.

    ..note:

    This function is outside of get_wordlist_as_raw because generators functions can't raise common
    exceptions os return values for wrong inputs.

    :param wordlist_handler: path to wordlist
    :type wordlist_handler: str

    :raises: WordlistNotFound
    """
    if not isinstance(wordlist_handler, file):
        raise TypeError("Expected file, got '%s' instead" % type(wordlist_handler))

    try:
        for line in wordlist_handler:
            yield line
    except IOError, e:
        raise WordlistNotFound("Error opening wordlist. Error: %s " % str(e))


#------------------------------------------------------------------------------
class _AbstractWordlist(object):
    """
    Abstract class for advanced wordlists.
    """
    __metaclass__ = ABCMeta

    #--------------------------------------------------------------------------
    @abstractproperty
    def binary_search(self, word, low_pos=0, high_pos=None):
        """
        Makes a binary search in the list and return the position of the word.

        Raises a ValueError exception if no coincidence found.

        low_pos and high_pos specifies the range between the function will search.

        :param word: The word to find.
        :type word: str

        :param low_pos: initial postion to the function starts searching.
        :type low_pos: Int

        :param high_pos: End postion to the function starts searching.
        :type high_pos: Int|None

        :return: Get the position fo the first search value.
        :rtype: Int

        :raises: ValueError
        """

    #--------------------------------------------------------------------------
    @abstractproperty
    def get_first(self, word, init=0):
        """
        Get the index of first coincidence or 'word', starting at init value.

        Raises a ValueError exception if no coincidence found.

        :param init: initial position to the function starts searching.
        :type init: Int

        :return: index of the first element found.
        :rtype: int

        :raises: ValueError
        """

    #--------------------------------------------------------------------------
    @abstractproperty
    def get_rfirst(self, word, init=0):
        """
        Get first coincidence, starting from the end. Raises a ValueError exception
        if no coincidence found.

        :param init: initial postion to the function starts searching.
        :type init: Int

        :return: Value of the first element found, stating at the end.
        :rtype: str

        :raises: ValueError
        """

    #--------------------------------------------------------------------------
    @abstractproperty
    def search_mutations(self, word, rules):
        """"""

    #--------------------------------------------------------------------------
    @abstractproperty
    def clone(self):
        """
        This method makes a clone of the object.

        :return: A copy of this object.
        """

    #----------------------------------------------------------------------
    def _raw_to_list(self, input_iterable):
        """
        Transform iterable input text into a list, without line breaks or any other special character.

        :param input_iterable: Input iterable info.
        :type input_iterable: file

        :return: generated list.
        :rtype: list(str)

        :raises: ValueError, TypeError
        """
        if input_iterable is None:
            raise TypeError("None is not iterable")
        if not hasattr(input_iterable, "__iter__"):
            raise TypeError("Object not iterable")

        results = []
        results_append = results.append
        for i in input_iterable:
            if not isinstance(i, basestring):
                try:
                    # Only numbres
                    float(i)
                    i = str(i)
                except TypeError:
                    try:
                        int(i)
                        i = str(i)
                    except TypeError:
                        continue

            # Remove line breaks and special chars
            v = i.replace("\n", "").replace("\t", "").replace("\r", "").strip()
            results_append(v)

        return results


#------------------------------------------------------------------------------
class WList(_AbstractWordlist):
    """
    Advanced wordlist that loads a wordlist as a list. This wordlist behaves
    as a list, removing break lines and carry returns.

    Example:

        >>> from golismero.api.text.wordlist import WList
        >>> a = WList("./wordlist/golismero/no_spiderable_urls.txt")
        >>> "exit" in a
        True
        >>> for p in a:
        ...   print p
        ...
        logout
        logoff
        exit
        sigout
        signout
        delete
        remove

    This wordlist allow to do some operations with wordlists:
    - Search matches of a word in the wordlist.
    - Binary search in wordlist.
    - Get first coincidence, start at begining or end of list.
    - Search matches of wordlist with mutations.
    """

    #--------------------------------------------------------------------------
    def search_mutations(self, word, rules):
        pass

    #--------------------------------------------------------------------------
    def __init__(self, wordlist):
        """
        :param wordlist: a file descriptor of the wordlist.
        :type wordlist: open()
        """

        if not wordlist:
            raise ValueError("Got empty wordlist")

        try:
            self.__wordlist = list(simple_word_list(wordlist))
        except IOError, e:
            raise IOError("Error when trying to open wordlist: %s" + str(e))

    #--------------------------------------------------------------------------
    def __getitem__(self, i):
        return self.__wordlist[i]

    #--------------------------------------------------------------------------
    def __setitem__(self, i, v):
        self.__wordlist[i] = v

    #--------------------------------------------------------------------------
    def __contains__(self, i):
        return i in self.__wordlist

    #--------------------------------------------------------------------------
    def __iter__(self):
        return self.__wordlist.__iter__()

    #--------------------------------------------------------------------------
    def __len__(self):
        return len(self.__wordlist)

    #--------------------------------------------------------------------------
    # Operations
    #--------------------------------------------------------------------------
    def binary_search(self, word, low_pos=0, high_pos=None):
        i = bisect.bisect_left(self.__wordlist, word, lo=low_pos, hi=high_pos if high_pos else len(high_pos))

        if i != len(self.__wordlist) and self.__wordlist[i] == word:
            return i

        raise ValueError()

    #--------------------------------------------------------------------------
    def get_first(self, word, init=0):
        i = bisect.bisect_left(self.__wordlist, word, lo=init)

        if i:
            return i

        raise ValueError()

    #--------------------------------------------------------------------------
    def get_rfirst(self, word, init=0):
        i = bisect.bisect_right(self.__wordlist, word, lo=init)

        if i:
            return i

        raise ValueError()

    #--------------------------------------------------------------------------
    def clone(self):
        m_temp = copy.copy(self)
        m_temp.__wordlist = copy.copy(self.__wordlist)

        return m_temp

    #--------------------------------------------------------------------------
    def pop(self):
        return self.__wordlist.pop()


#------------------------------------------------------------------------------
class WDict(object):
    """
    Advanced wordlist that loads a wordlist with a separator character as a dict, like:

    word list 1; second value of wordlist

    These line load as => {'word list 1':'second value of wordlist'}.
    """

    #--------------------------------------------------------------------------
    def __init__(self, wordlist, smart_load=False, separator = ";"):
        """
        Load a word list and conver it in a dict. The method used for the conversion
        are:

        Read line to line the file and split it using separatod specified as parameter. Then
        use the left value as key, and the right will be used as value of dict.

        .. note:
           If the file has repeated values for keys names, the values will be joined in the same
           key.

        Example:

        >>> f=open("wordlist.txt", "rU")
        >>> f.readlines()
        ['one; value1', 'two; value2', 'one; value3']
        >>> w = WDict("wordlist.txt")
        >>> w.matches_by_keys("one")
        {'one': [' value1', ' value3']}


        If you set to True the param 'smart_load', the WDict will try to detect if the values
        at the right of 'separator', found by the split, can be pooled as a list an put the values in it.

        Example:

        >>> f=open("wordlist.txt", "rU")
        >>> f.readlines()
        ['one; value1 value2, value3, value4 "value 5"', 'two; value6', 'one; value7']
        >>> w = WDict("wordlist.txt", smart_load=True)
        >>> w.matches_by_keys("one")
        {'one': ['value1', 'value2', 'value3', 'value4', 'value 5', 'value7']}


        :param wordlist: a file descriptor of the wordlist.
        :type wordllist: open()

        :param separator: value used to split the lines
        :type separator: str

        :param smart_load: Indicates if the wordlist must detect if the line has values that can be converted in a list.
        :type smart_load: bool
        """

        if not wordlist:
            raise ValueError("Empty wordlist got")
        if not separator:
            raise ValueError("Empty separator got")

        m_tmp_wordlist = None
        try:
            m_tmp_wordlist = wordlist.readlines()
        except IOError, e:
            raise IOError("Error when trying to open wordlist. Error: %s" % str(e))

        self.__wordlist = {}
        m_reg           = re.compile(r"([#A-Za-z\d]+|[\'\"][\w\d\s]+[\'\"])")
        for k in m_tmp_wordlist:
            v = k.replace("\n","").replace("\r","").split(separator,1)

            if len(v) < 2:
                continue

            if smart_load:
                m_values = [i.group(0).strip().replace("'","").replace("\"","") for i in m_reg.finditer(v[1])]

                try:
                    self.__wordlist[v[0]].extend(m_values)
                except KeyError:
                    self.__wordlist[v[0]] = []
                    self.__wordlist[v[0]].extend(m_values)
            else:
                try:
                    self.__wordlist[v[0]].append(v[1])
                except KeyError:
                    self.__wordlist[v[0]] = []
                    self.__wordlist[v[0]].append(v[1])

    #--------------------------------------------------------------------------
    def matches_by_keys(self, word):
        """
        Search a word passed as parameter in the keys's wordlist and return a list of lists with
        matches found.

        :param word: word to search.
        :type word: str.

        :return: a list with matches.
        :rtype: dict(KEY, list(VALUES))
        """

        if not word:
            return {}

        word = str(word)

        return { i:v for i, v in self.__wordlist.iteritems() if word == i}

    #--------------------------------------------------------------------------
    def matches_by_key_with_level(self, word):
        """
        Search a word passed as parameter in keys's wordlist and return a list of dicts with
        matches and level of correspondence.

        The matching level is a value between 0-1.

        :param word: word to search.
        :type word: str.

        :return: a list with matches and correpondences.
        :rtype: list(list(KEY, VALUE, LEVEL))
        """

        if not word:
            return [[]]

        word = str(word)

        m_return        = set()
        m_return_append = m_return.add
        for i, v in self.__wordlist.iteritems():
            if word in i:
                continue

            m_return_append((i, v, get_diff_ratio(word, i)))

        return m_return

    #--------------------------------------------------------------------------
    def matches_by_value(self, word):
        """
        Search a word passed as parameter in the values of wordlist and return a list of lists with
        matches found.

        :param word: word to search.
        :type word: str.

        :return: a list with matches.
        :rtype: dict(KEY, list(VALUES))
        """

        if not word:
            return {}

        word = str(word)

        m_return = {}

        for k, v in self.__wordlist.iteritems():
            if word not in v:
                continue

            for l in v:
                if word == l:
                    try:
                        m_return[k].add(l)
                    except KeyError:
                        m_return[k] = set()
                        m_return[k].add(l)

        return m_return

    #--------------------------------------------------------------------------
    def matches_by_value_with_level(self, word):
        """
        Search a word passed as parameter in values of wordlist and return a list of dicts with
        matches and level of correspondence.

        The matching level is a value between 0-1.

        :param word: word to search.
        :type word: str.

        :return: a list with matches and correpondences.
        :rtype: list(list(KEY, VALUE, LEVEL))
        """

        if not word:
            return []

        word = str(word)

        m_return        = set()
        m_return_append = m_return.add
        for v in self.__wordlist.itervalues():
            if word not in v:
                continue

            for l in v:
                if word == l:
                    m_return_append((l, v, get_diff_ratio(word, l)))

        return m_return

    #--------------------------------------------------------------------------
    def __getitem__(self, i):
        return self.__wordlist[i]

    #--------------------------------------------------------------------------
    def __setitem__(self, i, v):
        if not isinstance(v, list):
            raise ValueError("Excepted list type. Got '%s'" % type(v))

        self.__wordlist[i] = v

    #--------------------------------------------------------------------------
    def __contains__(self, i):
        return i in self.__wordlist

    #--------------------------------------------------------------------------
    def iteritems(self):
        return self.__wordlist.iteritems()

    #--------------------------------------------------------------------------
    def __iter__(self):
        return self.__wordlist.__iter__

    #--------------------------------------------------------------------------
    def __len__(self):
        return len(self.__wordlist)

    #--------------------------------------------------------------------------
    def itervalues(self):
        return self.__wordlist.itervalues()

    #--------------------------------------------------------------------------
    def iterkeys(self):
        return self.__wordlist.iterkeys()

    #--------------------------------------------------------------------------
    def clone(self):
        m_temp = copy.copy(self)
        m_temp.__wordlist = copy.copy(self.__wordlist)

        return m_temp


#------------------------------------------------------------------------------
# Singleton.
WordListLoader = _WordListLoader()
