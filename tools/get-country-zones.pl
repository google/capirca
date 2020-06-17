#!/usr/bin/perl
#
# Author: Paul Armstrong
#
# Downloads maps of countries to CIDR netblocks for the world and then turns
# them into definition files usable by Capirca

use strict;
use warnings;
use File::Find;

my @files;
my $destination = '../def/';
my $extension = '.net';

system("wget http://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz")
  == 0 or die "Unable to get all-zones.tar.gz: $?\n";

system("tar -zxf all-zones.tar.gz") == 0
  or die "Unable to untar all-zones.tar.gz: $?\n";

# We don't need these lying around
unlink("Copyrights.txt");
unlink("MD5SUM");
unlink("all-zones.tar.gz");

sub zone_files
{
  push @files, $File::Find::name if(/\.zone$/i);
}

find(\&zone_files, $ENV{PWD});

for my $file (@files)
{
  if($file =~ /^.*\/([a-z]{2})\.zone/)
  {
    my $country = $1;
    my $new_name = "$destination$country$extension";
    my $country_uc = uc($country);
    die "$file is zero bytes\n" if(!-s $file);
    open(OLDFILE, $file) or die "Unable to open $file: $!\n";
    open(NEWFILE, ">$new_name")
      or die "Unable to open $new_name: $!\n";
    while(<OLDFILE>)
    {
      chomp;
      if ($. == 1)
      {
        print NEWFILE "${country_uc}_NETBLOCKS = $_\n"
          or die "Unable to print to $new_name: $!\n";
      }
      else
      {
        print NEWFILE "               $_\n"
          or die "Unable to print to $new_name: $!\n";
      }
    }
    close(NEWFILE) or die "$new_name didn't close properly: $!\n";
    close(OLDFILE);
    die "$new_name is zero bytes\n" if(!-s $new_name);
    unlink($file); # clean up the originals.
  }
}
