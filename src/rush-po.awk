# This file is part of GNU Rush.
# Copyright (C) 2009-2016 Sergey Poznyakoff
#
# GNU Rush is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# GNU Rush is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Rush.  If not, see <http://www.gnu.org/licenses/>.

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

{ if (!text) start_line = NR }
/\\$/ { text = text substr($0,1,length($0)-1); next }
{ if (text) $0 = text $0; text = "" }

$1 == "exit" {
	gsub(/^[ \t]*exit[ \t][0-9]*[ \t]*/,"")
	if (gsub(/^@/, "")) {
		if (match($0, /^[^@].*/))
			next
	}
	printf("#: %s:%d\n", FILENAME, start_line)
	printf("msgid \"%s\"\n", $0)
	printf("msgstr \"\"\n\n")
	next
}
$1 == "usage-error" \
	|| $1 == "nologin-error" \
	|| $1 == "config-error" \
	|| $1 == "system-error" {
	gsub(/^[ \t]*[a-z][a-z]*-error[ \t][ \t]*/,"")
	printf("#: %s:%d\n", FILENAME, start_line)
	printf("msgid \"%s\"\n", $0)
	printf("msgstr \"\"\n\n")
}
	
