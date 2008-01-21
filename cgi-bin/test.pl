#!/usr/bin/perl
##
##  printenv -- demo CGI program which just prints its environment
##
use CGI qw/:standard/;
my $query = new CGI;

print "Content-type: text/html\n\n";
print <<EOD;
<HTML>
<BODY bgcolor=#ffffff textcolor=#000000>
<H1>CGI Support</h1>
<B>Test form</B><BR>
<FORM method="POST" ACTION="test.pl">
Input1 : <INPUT NAME="input1" value="" size="30" maxlength="30"><br>
Input2 : <INPUT NAME="input2" value="" size="30" maxlength="30"><br><br>
Option : <select name="option">
<option value="1">Option 1</option>
<option value="2">Option 2</option>
<option value="3">Option 3</option>
</select>
<br><br>
<input type="submit" value="Send">
</FORM>
<P>

EOD

if (param()) {
  print qq(<P><B>Form vars</B>\n<PRE>\n);
  foreach $p (param()) {
        print qq($p = '), param($p), qq('\n);
  }
  print qq(</pre>\n);
}

print qq(<P><B>Environment vars</B>\n<PRE>\n);

foreach $var (sort(keys(%ENV))) {
    $val = $ENV{$var};
    $val =~ s|\n|\\n|g;
    $val =~ s|"|\\"|g;
    print "${var}=\"${val}\"\n";
}

print qq(</pre>\n);
print qq(</body>\n</html>\n);
