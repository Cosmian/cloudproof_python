# -*- coding: utf-8 -*-
from abc import ABCMeta

from cloudproof_py.findex import Findex


class FindexBase(metaclass=ABCMeta):
    def __init__(self) -> None:
        self.findex: Findex
