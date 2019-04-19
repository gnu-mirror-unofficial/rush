# This file is part of GNU Rush.
# Copyright (C) 2009-2019 Sergey Poznyakoff
# Distributed under the terms of the GNU General Public License, either
# version 3, or (at your option) any later version. See file COPYING
# for the text of the license.

# Provide leading quote
1i\
"\\

# Provide trailing quote
$a\
"

# Remove empty lines and comments
/ *#/d
/^ *$/d
# Escape quotes and backslashes
s/["\]/\\&/g
# Add newline and continuation character at the end of each line
s/$/\\n\\/
# End

