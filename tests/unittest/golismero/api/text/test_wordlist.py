#!/usr/bin/python
# -*- coding: utf-8 -*-

import pytest
import os
import os.path

from golismero.api.text.wordlist import WordListLoader, WordlistNotFound, _AbstractWordlist
from golismero.api.localfile import LocalFile


#----------------------------------------------------------------------
# Aux functions
#----------------------------------------------------------------------
W_DIR = "plugin_tmp_dir"
W_NAME = "test_wordlist.txt"
W_PATH = os.path.join(W_DIR, W_NAME)


#----------------------------------------------------------------------
def _create_plugin_info():
    """Creates plugin folders and files"""
    # Create folder and wordlist file
    try:
        os.mkdir(W_DIR)
        open(W_PATH, "w").write("hello word\n")
    except os.error:
        pass


#----------------------------------------------------------------------
def _destroy_plugin_info():
    """Destroy plugin folders and files"""
    try:
        os.remove(W_PATH)
        os.rmdir(W_DIR)
    except os.error:
        pass


#--------------------------------------------------------------------------
# WordListLoader test
#--------------------------------------------------------------------------
class TestWordListLoader:

    #----------------------------------------------------------------------
    # ___load_wordlists_types Tests
    #----------------------------------------------------------------------
    def test__load_wordlists_types(self):
        pytest.raises(TypeError, WordListLoader._WordListLoader__load_wordlists, -1)
        pytest.raises(TypeError, WordListLoader._WordListLoader__load_wordlists, [])
        pytest.raises(TypeError, WordListLoader._WordListLoader__load_wordlists, dict())

    #----------------------------------------------------------------------
    def test__load_wordlists_not_exits(self):
        pytest.raises(ValueError, WordListLoader._WordListLoader__load_wordlists, "aaaaa")

    #----------------------------------------------------------------------
    def test__load_wordlists_input(self):
        # Reload wordlist
        WordListLoader._WordListLoader__load_wordlists("../../wordlist")

        # Check
        assert len(WordListLoader._WordListLoader__store) != 0

    #----------------------------------------------------------------------
    # __get_wordlist_descriptor Tests
    #----------------------------------------------------------------------
    def test__get_wordlist_descriptor_types(self):
        pytest.raises(TypeError, WordListLoader._WordListLoader__get_wordlist_descriptor, -1)
        pytest.raises(TypeError, WordListLoader._WordListLoader__get_wordlist_descriptor, [])
        pytest.raises(TypeError, WordListLoader._WordListLoader__get_wordlist_descriptor, dict())

    #----------------------------------------------------------------------
    def test__get_wordlist_descriptor_empty_input(self):
        pytest.raises(ValueError, WordListLoader._WordListLoader__get_wordlist_descriptor, "")

    #----------------------------------------------------------------------
    def test__get_wordlist_descriptor_not_exits_abs_path(self):
        LocalFile._LocalFile__plugin_path = os.getcwd()
        pytest.raises(WordlistNotFound, WordListLoader._WordListLoader__get_wordlist_descriptor, "aaaaa")

    #----------------------------------------------------------------------
    def test__get_wordlist_descriptor_exits_abs_path(self):
        # Config plugin
        LocalFile._LocalFile__plugin_path = os.getcwd()

        _create_plugin_info()

        try:
            wordlist_file = WordListLoader._WordListLoader__get_wordlist_descriptor(W_PATH)

            # Checks if wordlist is file
            wordlist_file == open(W_PATH, "rU")

            # Checks if wordlist is non file
            pytest.raises(WordlistNotFound, WordListLoader._WordListLoader__get_wordlist_descriptor, W_DIR)
        finally:
            _destroy_plugin_info()

    #----------------------------------------------------------------------
    def test__get_wordlist_descriptor_exits_in_plugin_path(self):
        # Config plugin
        LocalFile._LocalFile__plugin_path = os.path.abspath(W_DIR)

        _create_plugin_info()

        try:
            wordlist_file = WordListLoader._WordListLoader__get_wordlist_descriptor(W_PATH)

            # Checks if wordlist is file
            wordlist_file == wordlist_file == open(W_PATH, "rU")

            # Checks if wordlist is non file
            pytest.raises(WordlistNotFound, WordListLoader._WordListLoader__get_wordlist_descriptor, "plugin_tmp_dir")
        finally:
            _destroy_plugin_info()

    #----------------------------------------------------------------------
    def test__get_wordlist_with_word_wordlist(self):
        LocalFile._LocalFile__plugin_path = os.getcwd()
        pytest.raises(ValueError, WordListLoader._WordListLoader__get_wordlist_descriptor, "wordlist")

    #--------------------------------------------------------------------------
    # all_wordlist property test
    #----------------------------------------------------------------------
    def test_all_wordlist_property(self):
        # Set Config plugin
        LocalFile._LocalFile__plugin_path = os.path.abspath(W_DIR)

        # Create plugin wordlists
        _create_plugin_info()

        # Clean and configure new store
        WordListLoader._WordListLoader__store = {}
        WordListLoader._WordListLoader__load_wordlists(W_DIR)

        try:
            assert WordListLoader.all_wordlists == ["test_wordlist.txt"]
        finally:
            _destroy_plugin_info()


#--------------------------------------------------------------------------
# Raw2list in Abstract test
#--------------------------------------------------------------------------
class Concrete(_AbstractWordlist):
    def get_first(self, word, init=0):
        pass

    def binary_search(self, word, low_pos=0, high_pos=None):
        pass

    def search_mutations(self, word, rules):
        pass

    def clone(self):
        pass

    def get_rfirst(self, word, init=0):
        pass


#--------------------------------------------------------------------------
class TestRaw2List:
    #----------------------------------------------------------------------
    def setup_class(self):
        """Comment"""
        self.o = Concrete()
        self.func = self.o._raw_to_list

    #----------------------------------------------------------------------
    def test_types(self):
        pytest.raises(TypeError, self.func, None)
        pytest.raises(TypeError, self.func, 0)
        pytest.raises(TypeError, self.func, "")

    #----------------------------------------------------------------------
    def test_empty_input(self):
        assert self.func([]) == []

    #----------------------------------------------------------------------
    def test_empty_wrong_input(self):
        assert self.func([1, 2, "a"]) == ["1", "2", "a"]
        assert self.func([1, "ñ", "a"]) == ["1", "\xc3\xb1", "a"]
        assert self.func([1.1, "b", "a"]) == ["1.1", "b", "a"]
        assert self.func([[], "c", "a"]) == ["c", "a"]

    #----------------------------------------------------------------------
    def test_input(self):
        # Normal
        assert self.func(["hello", "world"]) == ["hello", "world"]
        # With trailer
        assert self.func(["hello    ", "    world"]) == ["hello", "world"]
        # With special chars
        assert self.func(["hello    \n   ", " \t \r  world"]) == ["hello", "world"]


#--------------------------------------------------------------------------
# Raw wordlist test
#--------------------------------------------------------------------------
class TestRawWordLists:

    #----------------------------------------------------------------------
    def setup_class(self):
        """Comment"""
        self.func = WordListLoader.get_wordlist_as_raw

    #----------------------------------------------------------------------
    def test_types(self):
        pytest.raises(TypeError, self.func, None)
        pytest.raises(TypeError, self.func, 0)
        pytest.raises(TypeError, self.func, [])
        pytest.raises(TypeError, self.func, dict())

    #----------------------------------------------------------------------
    def test_empty_input(self):
        pytest.raises(ValueError, self.func, "")

    #----------------------------------------------------------------------
    def test_input(self):
        _create_plugin_info()

        # Check for types
        assert type(WordListLoader.get_wordlist_as_raw(W_NAME)) == type(x for x in xrange(10))

        # Check for values in generators
        s1 = set(WordListLoader.get_wordlist_as_raw(W_PATH))
        s2 = set((x for x in ["hello word"]))
        assert s1.intersection(s2) == set([])

        _destroy_plugin_info()