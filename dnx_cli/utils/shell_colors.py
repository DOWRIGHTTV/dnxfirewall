#!/usr/bin/env python3

# initial work commissioned to: Zach - https://codeberg.org/zach

from __future__ import annotations

from typing import Optional, NamedTuple

__all__ = (
    'text', 'styles'
)

class _BG(NamedTuple):
    black:      str = '\033[40m'
    red:        str = '\033[41m'
    green:      str = '\033[42m'
    orange:     str = '\033[43m'
    blue:       str = '\033[44m'
    purple:     str = '\033[45m'
    cyan:       str = '\033[46m'
    lightgrey:  str = '\033[47m'

class _FG(NamedTuple):
    black:      str = '\033[30m'
    red:        str = '\033[31m'
    green:      str = '\033[32m'
    orange:     str = '\033[33m'
    blue:       str = '\033[34m'
    purple:     str = '\033[35m'
    cyan:       str = '\033[36m'
    lightgrey:  str = '\033[37m'
    darkgrey:   str = '\033[90m'
    lightred:   str = '\033[91m'
    lightgreen: str = '\033[92m'
    yellow:     str = '\033[93m'
    lightblue:  str = '\033[94m'
    pink:       str = '\033[95m'
    lightcyan:  str = '\033[96m'

class _Styles(NamedTuple):
    # DISABLED STYLES
    # disable='\033[02m'
    # reverse='\033[07m'
    # strikethrough='\033[09m'
    # invisible='\033[08m'
    reset:      str = '\033[0m'
    bold:       str = '\033[01m'
    underline:  str = '\033[04m'


# INITIALIZING NAMED TUPLES FOR EXPORT
bg = _BG()
fg = _FG()
styles = _Styles()

# class colors:
#     def makeDisable(skk):
#        return styles.disable + '{}'.format(skk) + styles.reset
#
#     def reverseEffect(skk):
#        return styles.reverse + '{}'.format(skk) + styles.reset
#
#     def strikethroughEffect(skk):
#        return styles.strikethrough + '{}'.format(skk) + styles.reset
#
#     def invisbleEffect(skk):
#        return styles.invisible + '{}'.format(skk) + styles.reset

class text:
    # BG OPTIONS
    # bg.black
    # bg.red
    # bg.green
    # bg.orange
    # bg.blue
    # bg.cyan
    # bg.lightgrey
    BACKGROUND = bg.black

    @staticmethod
    def black(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.black}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def red(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.red}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def green(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.green}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def orange(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.orange}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def blue(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.blue}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def purple(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.purple}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def cyan(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.cyan}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def lightgrey(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.lightgrey}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def darkgrey(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.darkgrey}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def lightred(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.lightred}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def lightgreen(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.lightgreen}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def yellow(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.yellow}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def lightblue(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.lightblue}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def pink(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.pink}{style if style else ""}{t}{styles.reset}'

    @staticmethod
    def lightcyan(t: str, style: Optional[_Styles] = styles.bold):
        return f'{text.BACKGROUND}{fg.lightcyan}{style if style else ""}{t}{styles.reset}'
