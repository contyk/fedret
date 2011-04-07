#!/usr/bin/env perl

# fedret, Fedora Review Tool, MIT/X Consortium License
#
# © 2011 Petr Sabata <psabata@redhat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

use strict;
use warnings;
use Carp;
use Getopt::Long;
use File::Path qw(remove_tree);
use File::Copy qw(cp);

use Archive::RPM;
use Text::CSV;
use Digest::MD5;
use WWW::Curl::Easy;

our $VERSION = "0.1";

use constant SYSPATH => '/usr/share/fedret';
use constant USERPATH => "$ENV{HOME}/.fedora/fedret";

our $output;
# Options
our $tmpl = 'default';                  # The review template to use
our $srpm;                              # Path to the SRPM to review
our $specfile;                          # Path to the Spec file to review
our $help;                              # Should we just display the usage information?
our $tmpldir = '.';                     # Templates dir
our @mock;                              # Mock buildroots to test
our @koji;                              # Koji buildroots to test
our $copy;                              # Copy expdir to the current directory
our $outfile = './review.txt';          # Write review output to this file
# Checklist
our @must;                              # MUST review items
our @should;                            # SHOULD review items
# Package variables
our $name;                              # Package name
our $version;                           # Package version
our $release;                           # Package release
our $expdir;                            # Directory with extracted SRPM
our $spec;                              # Spec filename
our @sources;                           # Sources filenames
our @patches;                           # Patches filenames
# Review indicators
our %ind = (
    ok      => '[  OK  ]',
    fail    => '[ FAIL ]',
    note    => '[ NOTE ]',
    na      => '[  --  ]',
    ne      => '[  ??  ]',
);

# Say a message to stderr
# Args: message
sub debug {
    print { *STDERR } shift . "\n";
    return 1;
}

# Display usage
# Args: (none)
sub usage {
    print { *STDERR } <<"    EOF";
fedret <options>
REQUIRED
    -p|--package SRPM               Path to the SRPM to review
    -s|--spec SPEC                  Path to the Spec file to review
OPTIONAL
    -c|--copy                       Copy the extracted SRPM to ./build
    -t|--template TEMPLATE          Use TEMPLATE for review
    -d|--templatedir DIR            Load the TEMPLATE from DIR
    -m|--mock BR[ BR2[ ...]]        Build in mock buildroots BR, BR2, ...
    -k|--koji BR[ BR2[ ...]]        Build in koji buildroots BR, BR2, ...
    EOF
    return 1;
}

# Prompt for something
# Args: prompt string, default answer, [@acceptable answers]
sub prompt {
    my ($prompt, $default, @variants) = @_;
    my $variants;
    my $resp;
    my $check;
    map { $_ = uc($_) if /^\Q${default}\E$/is } @variants;
    $variants = join(q{/}, @variants);
    do {
        local $| = 1;
        print "\a${prompt} ";
        if ($variants) {
            print "(${variants}): ";
        } else {
            print "[${default}]: ";
        }
        $resp = <STDIN>;
        if (!defined($resp)) {
            print "${default}\n";
        } else {
           chomp $resp if $resp;
        }
        $resp = $resp ? $resp : $default;
        if ($variants) {
            if (scalar(grep { /^\Q${resp}\E$/is } @variants)) {
                $check = 1;
            } else {
                print "Sorry, response '${resp}' not understood.\n";
                $check = 0;
            }
        } else {
            $check = 1;
        }
    } while (!$check);
    return $resp;
}

# Display OK
# Args: (none)
sub okay {
    print "${ind{ok}}\n";
    return 1;
}

# Display FAIL
# Args: (none)
sub fail {
    print "${ind{fail}}\n";
    return 1;
}

# Read file
# Args: path, buffer
sub readfile {
    my $path = shift or return 0;
    my $buf = shift or return 0;
    open my $fh ,'<', $path or die "Cannot open ${path}: $!";
    while (my $line = <$fh>) {
        ${$buf}.= $line;
    }
    close $fh or die "Cannot close ${path}: $!";
    return 1;
}

# Check options
# Args: (none)
sub checkopts {
    if ($help) {
        usage();
        exit;
    }
    if (!defined($srpm) || ! -f $srpm) {
        print { *STDERR } "SRPM not defined or does not exist!\n";
        exit 1;
    }
    if (!defined($specfile) || ! -f $specfile) {
        print { *STDERR } "Spec file not defined or does not exist!\n";
        exit 1;
    }
    for my $tmplpath ($tmpldir, USERPATH, SYSPATH) {
        if (-f "${tmplpath}/${tmpl}") {
            $tmpl = "${tmplpath}/${tmpl}";
            last;
        }
    }
    if (! -f $tmpl) {
        print { *STDERR  } "The specified template cannot be found!\n";
        exit 1;
    }
    writereview();
    return 1;
}

# Check if SRPM Spec and Spec are the same
# Args: (none)
sub checkspec {
    my $md5 = Digest::MD5->new;
    my ($srpmspecsum, $specfilesum);
    open my $srpmspecfh, '<', "${expdir}/${spec}" or die "Cannot open ${expdir}/${spec}: $!";
    $md5->addfile($srpmspecfh);
    close $srpmspecfh or die "Cannot close ${expdir}/${spec}: $!";
    $srpmspecsum = $md5->hexdigest;
    $md5->reset;
    open my $specfilefh, '<', "${specfile}" or die "Cannot open ${specfile}: $!";
    $md5->addfile($specfilefh);
    close $specfilefh or die "Cannot close ${specfile}: $!";
    $specfilesum = $md5->hexdigest;
    if ($specfilesum eq $srpmspecsum) {
        return 1;
    } else {
        debug("Spec file sum: ${specfilesum}");
        debug("SRPM spec file sum: ${srpmspecsum}");
        return 0;
    }
}

# Loads the template
# Args: (none)
sub loadtemplate {
    my $csv = Text::CSV->new({binary => 1});
    open my $fh, '<', $tmpl or die "Cannot open ${tmpl}: $!";
    while (my $rec = $csv->getline($fh)) {
        if ($rec->[0] =~ m/MUST/osi) {
            push @must, $rec->[1];
            next;
        }
        if ($rec->[0] =~ m/SHOULD/osi) {
            push @should, $rec->[1];
            next;
        }
    }
    close $fh or die "Cannot close ${tmpl}: $!";
    return 1;
}

# Build a SRPM
# Args: [mock root], [kojibool]
sub build {
    my $buildroot = shift;
    my $koji = shift;
    my $rc;
    if (! -d "${expdir}/build") {
        mkdir "${expdir}/build" or die "Cannot create ${expdir}/build: $!";
    }
    local $| = 1;
    if ($buildroot) {
        if (!$koji) {
            print "Building (${buildroot}) ${srpm}... ";
            $rc = system("mock -q -r ${buildroot} --resultdir ./build ${srpm} 2>${expdir}/build/${buildroot}.stderr");
        } else {
            print "Building (${buildroot} @ koji) ${srpm}...";
            $rc = system("koji build --scratch ${buildroot} ${srpm} >${expdir}/build/koji.${buildroot}.stdout 2>${expdir}/build/koji.${buildroot}.stderr");
        }
    } else {
        print "Building (local) ${srpm}... ";
        $rc = system("rpmbuild --rebuild ${srpm} 1>${expdir}/build/stdout 2>${expdir}/build/stderr");
    }
    return $rc == 0 ? 1 : 0;
}

# Test sources
# Args: (none)
sub testsources() {
    debug('Sources MD5 checksum:');
    for my $src (@sources) {
        my $sum = Digest::MD5->new;
        open my $fh, q{<}, "${expdir}/${src}" or die "Cannot read ${src}: $!";
        $sum->addfile($fh);
        close $fh or die "Cannot close ${src}: $!";
        debug("${src}: ".$sum->hexdigest);
    }
    debug('-' x 25);
    my $buf; readfile("${expdir}/${spec}", \$buf);
    my @specsrc = grep { /^Source\d+:/ } (split /\n/, $buf);
    map { s/^Source\d+:\s*([^\s#]+).*$/$1/o; $_ = expand($_) } @specsrc;
    for (@specsrc) {
        next unless ?^http://.+?so;
        # TODO: Download sources to ./upstream -- ask for URL correction, don't use perl Curl...
    }
}

# Expand spec string
# Args: string
sub expand {
    my $str = shift;
    $str =~ s/%{name}/${name}/sog;
    $str =~ s/%{version}/${version}/sog;
    $str =~ s/%{release}/${release}/sog;
    return $str;
}

# Write review output to a file
# Args: review output
sub writereview {
    open my $revfh, '>', $outfile or die "Cannot write to '${outfile}': $!";
    print { $revfh } shift;
    close $revfh or die "Cannot close '${outfile}': $!";
}

GetOptions(
    'template|t=s'     => \$tmpl,
    'package|p=s'      => \$srpm,
    'spec|s=s'         => \$specfile,
    'help|h|?'         => \$help,
    'templatedir|d=s'  => \$tmpldir,
    'mock|m=s{,}'      => \@mock,
    'koji|k=s{,}'      => \@koji,
    'copy|c'           => \$copy,
    'output|o=s'       => \$outfile,
);
checkopts();
loadtemplate();
my $srpma = Archive::RPM->new(rpm => $srpm, auto_cleanup => 1);
if (! $srpma->is_srpm) {
    print { *STDERR } "'$srpm' is not a valid source RPM!\n";
    exit 1;
}
# Package NVR
$srpma->filename =~ m|^.*?/([^/]+)-([^-]+)-([^.-]+(\.[^.-]+)*)?\.src\.rpm$|s;
$name = $1; $version = $2; $release = $3;
# Temporary directory with extracted RPM
$expdir = $srpma->first_file; $expdir =~ s?/[^/]+$??sx;
# Spec file, patches, sources
for my $file ($srpma->files) {
    $file =~ s|^.*?/([^/]+)$|$1|so;
    if ($file eq "${name}.spec") {
        $spec = $file;
        next;
    }
    if ($file =~ /\.patch$/so) {
        push @patches, $file;
        next;
    }
    push @sources, $file;
}

if (!checkspec()) {
    print { *STDERR } "Spec files don't match!\n";
    exit 1;
}

if ($copy) {
    remove_tree('./exploded/');
    mkdir('./exploded') or die "Cannot create directory 'exploded': $!";
    opendir my $dh, $expdir or die "Cannot read directory ${expdir}: $!";
    my @expfiles = readdir $dh;
    closedir $dh or die "Cannot close directory ${expdir}: $!";
    for my $file (@expfiles) {
        next if $file =~ /^\.\.?$/;
        cp("${expdir}/${file}", './exploded/') or die "Cannot copy '${expdir}/${file} to ./exploded/: $!";
    }
}

$output.= "Package: ${name}\n";
$output.= "Version: ${version}\n";
$output.= "Release: ${release}\n";
$output.= 'Sources: '.join(q{, }, @sources)."\n";
$output.= 'Patches: '.join(q{, }, @patches)."\n";
$output.= ('-' x 10)."\n";

print $output;

my $resp;
$resp = prompt('Build the package locally?', 'y', ('y', 'n'));
if (lc($resp) eq 'y') {
    if (build()) {
        okay();
        $output.= "Package successfully built locally.\n";
    } else {
        fail();
        my $buf; readfile("${expdir}/build/stderr", \$buf);
        debug($buf);
        $output.= "Package failed to build locally!\n";
    }
}
if (@mock) {
    $resp = prompt('Build the package in '.join(q{, }, @mock).' mock buildroot(s)?', 'y', ('y', 'n'));
    if (lc($resp) eq 'y') {
        for my $buildroot (@mock) {
            if (build($buildroot)) {
                okay();
                $output.= "Package successfully built in mock, ${buildroot}.\n";
            } else {
                fail();
                my $buf; readfile("${expdir}/build/${buildroot}.stderr", \$buf);
                debug($buf);
                $output.= "Package failed to build in mock, ${buildroot}.\n";
            }
        }
    }
}
if (@koji) {
    $resp = prompt('Build the package in '.join(q{, }, @koji).' koji buildroot(s)?', 'n', ('y', 'n'));
    if (lc($resp) eq 'y') {
        for my $buildroot (@koji) {
            if (build($buildroot, 1)) {
                okay();
                $output.= "Package successfully built in koji, ${buildroot}.\n";
            } else {
                fail();
                my $buf; readfile("${expdir}/build/koji.${buildroot}.stdout", \$buf);
                debug($buf);
                $output.= "Package failed to build in koji, ${buildroot}.\n";
            }
        }
    }
}

# TODO: Test sources against upstream

$resp = prompt("Review the package using '${tmpl}' template?", 'n', ('y', 'n'));

if (lc($resp) eq 'y') {
    print "OK -- package complies with this item\n";
    print "FAIL -- package does not comply with this item\n";
    print "NOTE -- a special case, described in a note\n";
    print "NA -- this item is not applicable\n";
    print "NE -- this item hasn't been evaluated\n";
    print "BACK -- go to the previous question\n";
    if (@must) {
        print "\n";
        $output.= "\n";
        print "Package MUST:\n";
        print "-------------\n";
        $output.= "MUST items:\n";
        # This is a DIRTY hack
        for (my $item = 0; $item < scalar(@must); $item++) {
            $resp = prompt($must[$item], 'ne', ('ok', 'fail', 'note', 'na', 'ne', 'back'));
            if (lc($resp) eq 'back') {
                if ($item > 0) {
                    $output =~ s/\n[^\n]*$//s;
                    $item--;
                }
                $item--;
            } else {
                $output.= "${ind{${resp}}} ${must[${item}]}\n";
            }
        }
    }
    if (@should) {
        print "\n";
        $output.= "\n";
        print "Package SHOULD:\n";
        print "---------------\n";
        $output.= "SHOULD items:\n";
        # This is a DIRTY hack
        for (my $item = 0; $item < scalar(@should); $item++) {
            $resp = prompt($should[$item], 'ne', ('ok', 'fail', 'note', 'na', 'ne', 'back'));
            if (lc($resp) eq 'back') {
                if ($item > 0) {
                    $output =~ s/\n[^\n]*$//s;
                    $item--;
                }
                $item--;
            } else {
                $output.= "${ind{${resp}}} ${should[${item}]}\n";
            }
        }
    }
}

$output.= "\n";
$output.= "NOTES:\n";
$output.= "------\n\n";

# Final

print "\n";
writereview($output);
print "Review output: ${outfile}\n";
