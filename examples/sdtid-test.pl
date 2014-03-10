#!/usr/bin/perl -w

use strict;
use XML::LibXML;

my $stoken = "../stoken";
my $tc = "./TokenConverter";

sub add_str_node($$$)
{
	my ($parent, $name, $value) = @_;
	my $doc = $parent->ownerDocument;
	my $node = $doc->createElement($name);
	$node->appendChild($doc->createTextNode($value));
	$parent->appendChild($node);
}

sub rand_str
{
	my ($len) = @_;
	if (!defined($len)) {
		$len = int(rand() * 30) + 5;
	}
	my $ret = "";
	for (my $i = 0; $i < $len; $i++) {
		$ret .= chr(32 + int(rand() * 95));
	}
	return $ret;
}

sub rand_bool()
{
	return int(rand() * 2);
}

sub random_doc()
{
	my $doc = XML::LibXML::Document->new('1.0');
	my $root = $doc->createElement("TKNBatch");
	$doc->setDocumentElement($root);

	my $node = $doc->createElement("TKNHeader");
	$root->appendChild($node);
	add_str_node($node, "Version", "0");
	add_str_node($node, "Origin", rand_str());
	add_str_node($node, "Dest", rand_str());
	add_str_node($node, "Name", rand_str());
	add_str_node($node, "FirstToken", rand_str());
	add_str_node($node, "LastToken", rand_str());
# NumTokens: default
	add_str_node($node, "DefAddPIN", rand_bool());
	add_str_node($node, "DefLocalPIN", rand_bool());
	add_str_node($node, "DefCopyProtection", rand_bool());
	add_str_node($node, "DefPinType", rand_bool());
	add_str_node($node, "DefKeypad", rand_bool());
	add_str_node($node, "DefProtLevel", rand_bool());
	add_str_node($node, "DefRevision", rand_bool());
	add_str_node($node, "DefTimeDerivedSeeds", rand_bool());
	add_str_node($node, "DefAppDerivedSeeds", rand_bool());
# DefFormFactor: default
# HeaderMAC: computed

	my $tkn = $doc->createElement("TKN");
	$root->appendChild($tkn);
# SN: random
# Seed: random
	add_str_node($tkn, "UserFirstName", rand_str());
	add_str_node($tkn, "UserLastName", rand_str());
	add_str_node($tkn, "UserLogin", rand_str());

	$node = $doc->createElement("TokenAttributes");
	$tkn->appendChild($node);
# DeviceSerialNumber: blank
	add_str_node($node, "Nickname", rand_str());
# TokenMAC: computed

	$node = $doc->createElement("TKNTrailer");
	$root->appendChild($node);
	add_str_node($node, "BatchSignature", rand_str(100));
	add_str_node($node, "BatchCertificate", rand_str(500));
	return $doc;
}

#
# MAIN
#

while (1) {
	my $doc = random_doc();
	open(F, ">tpl.xml") or die;
	print F $doc->toString(1);
	close(F);

	system("$stoken export --random --template tpl.xml --sdtid > out.sdtid") == 0
		or die "can't run stoken";
	system("$tc out.sdtid > ctf.txt") == 0 or die "TokenConverter failed";

	system("$stoken show --file ctf.txt --seed | head -n 2 > seed.txt")
		== 0 or die "can't read seed from ctf";
	system("$stoken show --file out.sdtid --seed | head -n 2 > seed-test.txt")
		== 0 or die "can't read seed from sdtid";

	system("cmp seed.txt seed-test.txt") == 0 or die "seed mismatch";
}
