#!/usr/bin/perl -w

# win32deps.pl - lists all DLLs required to run an .exe file
# sample usage: win32deps.pl .libs/stoken-gui.exe
#
# This runs under Fedora with the cross mingw packages installed.  (i.e.
# it is not intended for native builds on Windows)

use strict;
use POSIX;

my $sysroot;
my %blacklist = (
	"advapi32.dll" => 1,
	"comctl32.dll" => 1,
	"comdlg32.dll" => 1,
	"dnsapi.dll" => 1,
	"gdi32.dll" => 1,
	"gdiplus.dll" => 1,
	"imm32.dll" => 1,
	"iphlpapi.dll" => 1,
	"kernel32.dll" => 1,
	"msimg32.dll" => 1,
	"msvcrt.dll" => 1,
	"ole32.dll" => 1,
	"shell32.dll" => 1,
	"shlwapi.dll" => 1,
	"user32.dll" => 1,
	"usp10.dll" => 1,
	"winmm.dll" => 1,
	"winspool.drv" => 1,
	"ws2_32.dll" => 1,
	"dwmapi.dll" => 1,
	"SETUPAPI.dll" => 1,
	"setupapi.dll" => 1,
);

my $CC = "i686-w64-mingw32-gcc";
my $OBJDUMP = "mingw-objdump";

sub run($)
{
	my ($cmd) = @_;
	my $out = `$cmd`;
	if (WIFEXITED($?) && WEXITSTATUS($?)) {
		die "command failed: '$cmd'";
	}
	chomp($out);
	return $out;
}

sub get_deps($)
{
	my ($pe) = @_;
	my @raw = split(/[\r\n]+/, run("$OBJDUMP -p '$pe'"));
	my @deps;
	foreach (@raw) {
		if (m/DLL Name: (\S+)/) {
			push(@deps, $1);
		}
	}
	return \@deps;
}

sub find_dll($)
{
	my ($dll) = @_;
	my @paths = (".", ".libs", "$sysroot/mingw/bin");

	foreach my $p (@paths) {
		my $x = "$p/$dll";
		return $x if (-e $x);
	}
	die "can't find '$dll'";
}

# MAIN

$sysroot = run("$CC -print-sysroot");
if (!-e $sysroot) {
	die "invalid sysroot: $sysroot";
}

my $exe = shift @ARGV;
if (!defined($exe) || !-e $exe) {
	die "usage: $0 <path_to_exe>";
}

my %visited;
my @deplist;

my @todo = ( $exe );

while (my $dep = pop(@todo)) {
	my $list = get_deps($dep);
	foreach my $dll (@$list) {
		my $lower = $dll;
		$lower =~ tr/A-Z/a-z/;
		if (!defined($visited{$dll}) && !defined($blacklist{$lower})) {
			my $dllpath = find_dll($dll);
			push(@todo, $dllpath);
			push(@deplist, $dllpath);
			$visited{$dll} = 1;
		}
	}
}

foreach my $x (sort(@deplist)) {
	print "$x\n";
}

exit(0);
