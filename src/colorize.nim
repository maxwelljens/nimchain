# Copyright (c) 2017 Molnár Márk

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

proc reset(): string {.procvar.} = "\e[0m"

# foreground colors
proc fgRed*(s: string): string {.procvar.} = "\e[31m" & s & reset()
proc fgBlack*(s: string): string {.procvar.} = "\e[30m" & s & reset()
proc fgGreen*(s: string): string {.procvar.} = "\e[32m" & s & reset()
proc fgYellow*(s: string): string {.procvar.} = "\e[33m" & s & reset()
proc fgBlue*(s: string): string {.procvar.} = "\e[34m" & s & reset()
proc fgMagenta*(s: string): string {.procvar.} = "\e[35m" & s & reset()
proc fgCyan*(s: string): string {.procvar.} = "\e[36m" & s & reset()
proc fgLightGray*(s: string): string {.procvar.} = "\e[37m" & s & reset()
proc fgDarkGray*(s: string): string {.procvar.} = "\e[90m" & s & reset()
proc fgLightRed*(s: string): string {.procvar.} = "\e[91m" & s & reset()
proc fgLightGreen*(s: string): string {.procvar.} = "\e[92m" & s & reset()
proc fgLightYellow*(s: string): string {.procvar.} = "\e[93m" & s & reset()
proc fgLightBlue*(s: string): string {.procvar.} = "\e[94m" & s & reset()
proc fgLightMagenta*(s: string): string {.procvar.} = "\e[95m" & s & reset()
proc fgLightCyan*(s: string): string {.procvar.} = "\e[96m" & s & reset()
proc fgWhite*(s: string): string {.procvar.} = "\e[97m" & s & reset()

# background colors
proc bgBlack*(s: string): string {.procvar.} = "\e[40m" & s & reset()
proc bgRed*(s: string): string {.procvar.} = "\e[41m" & s & reset()
proc bgGreen*(s: string): string {.procvar.} = "\e[42m" & s & reset()
proc bgYellow*(s: string): string {.procvar.} = "\e[43m" & s & reset()
proc bgBlue*(s: string): string {.procvar.} = "\e[44m" & s & reset()
proc bgMagenta*(s: string): string {.procvar.} = "\e[45m" & s & reset()
proc bgCyan*(s: string): string {.procvar.} = "\e[46m" & s & reset()
proc bgLightGray*(s: string): string {.procvar.} = "\e[47m" & s & reset()
proc bgDarkGray*(s: string): string {.procvar.} = "\e[100m" & s & reset()
proc bgLightRed*(s: string): string {.procvar.} = "\e[101m" & s & reset()
proc bgLightGreen*(s: string): string {.procvar.} = "\e[102m" & s & reset()
proc bgLightYellow*(s: string): string {.procvar.} = "\e[103m" & s & reset()
proc bgLightBlue*(s: string): string {.procvar.} = "\e[104m" & s & reset()
proc bgLightMagenta*(s: string): string {.procvar.} = "\e[105m" & s & reset()
proc bgLightCyan*(s: string): string {.procvar.} = "\e[106m" & s & reset()
proc bgWhite*(s: string): string {.procvar.} = "\e[107m" & s & reset()

# formatting functions
proc bold*(s: string): string {.procvar.} = "\e[1m" & s & reset()
proc underline*(s: string): string {.procvar.} = "\e[4m" & s & reset()
proc hidden*(s: string): string {.procvar.} = "\e[8m" & s & reset()
proc invert*(s: string): string {.procvar.} = "\e[7m" & s & reset()
