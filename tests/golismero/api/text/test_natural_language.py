#!/usr/bin/python
# -*- coding: utf-8 -*-

import pytest

from golismero.api.text.natural_language import get_words


#--------------------------------------------------------------------------
# Get words test
#--------------------------------------------------------------------------
class TestGetWords:

    #----------------------------------------------------------------------
    def test_types_param1(self):
        pytest.raises(TypeError, get_words, None)
        pytest.raises(TypeError, get_words, 0)
        pytest.raises(TypeError, get_words, [])
        pytest.raises(TypeError, get_words, dict())

    #----------------------------------------------------------------------
    def test_types_param2(self):
        pytest.raises(TypeError, get_words, "hello world", [])
        pytest.raises(TypeError, get_words, "hello world", "0")
        pytest.raises(ValueError, get_words, "hello world", -1)

    #----------------------------------------------------------------------
    def test_types_param3(self):
        pytest.raises(TypeError, get_words, "hello world", None, [])
        pytest.raises(TypeError, get_words, "hello world", None, "0")
        pytest.raises(ValueError, get_words, "hello world", None, -1)

    #----------------------------------------------------------------------
    def test_empty_imput(self):
        assert get_words("") == set([])

    #----------------------------------------------------------------------
    def test_normal_input(self):
        assert get_words("hello") == set(["hello"])
        assert get_words("hello world") == set(["hello", "world"])

    #----------------------------------------------------------------------
    def test_input_with_params(self):
        assert get_words("hello world", 6) == set([])
        assert get_words("hello world bye", 4) == set(["hello", "world"])
        assert get_words("hello world bye goooodbye", 4, 6) == set(["hello", "world"])

