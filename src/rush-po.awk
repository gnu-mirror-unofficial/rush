# This file is part of Rush.
# Copyright (C) 2009 Sergey Poznyakoff
#
# Rush is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Rush is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Rush.  If not, see <http://www.gnu.org/licenses/>.

BEGIN {
	print "# SOME DESCRIPTIVE TITLE."
        print "#, fuzzy"
	print "msgid \"\""
	print "msgstr \"\""
	print "\"Project-Id-Version: rush-config ADDITIONAL-DATA \\n\""
	print "\"PO-Revision-Date: YEAR-MO-DA HO:MI +ZONE\\n\""
	print "\"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n\""
        print "\"Language-Team: LANGUAGE <LL@li.org>\\n\""
	print "\"MIME-Version: 1.0\\n\""
	print "\"Content-Type: text/plain; charset=CHARSET\\n\""
	print "\"Content-Transfer-Encoding: 8bit\\n\""
	print ""
}

/\\$/ { text = text substr($0,1,length($0)-1); next }
{ if (text) $0 = text $0; text = "" }
$1 == "exit" {
	gsub(/^[ \t]+exit[ \t][0-9]*/,"")
	printf("#: %s:%d\n", FILENAME, NR)
	printf("msgid \"%s\"\n", $0)
	printf("msgstr \"\"\n\n")
}
	
