#!/usr/bin/env perl
use Getopt::Std;
use Config::Properties;
use Log::Handler;
use EnvProperties;
use LogSetup;
use X11::Terminal::XTerm;

use constant SLEEP_TIME => 0;

my $properties_file = 'end2end-tester.properties';
my $log_file = 'end2end-tester.log';

sub help
  {
      print <<HELP;
$0 [-h] [-p <properties file>] [-a <attack file>] [-l <logfile>]

    h - Print out this help message.
    p - Properties file.
        DEFAULT: $properties_file
    l - Log file.
        DEFAULT: $log_file
    a - Attack file name.
HELP
    exit(1);
  }

# Handle arguments
my %opts;
getopts('hp:l:a:',\%opts);

if(defined $opts{h})
{
    help();
}

if(defined $opts{p})
{
    $properties_file = $opts{p};
}

if(defined $opts{l})
{
    $log_file = $opts{l};
}

my $attack_file;

if(defined $opts{a})
{
    $attack_file = $opts{a};
}

my $properties = EnvProperties->new($properties_file);

my $lsu = LogSetup->new($properties,$log_file);

my $log = $lsu->logger;

$log->debug("Begin processing");

my $pid1 = fork();
if(!$pid1)
{
    chdir '../../taxii-communications';
    #sleep SLEEP_TIME;

    `xterm -title 'Attack Xmit' -hold -geometry 80x20+10+10 -fa 'Monospace' -fs 12 -e ./attackXmitD.py -d`;
}
else
{
    my $pid2 = fork();
    if(!$pid2)
    {
        chdir '../../taxii-communications';
        sleep SLEEP_TIME;
    `xterm -title 'Attack Rcv' -hold -geometry 80x20+900+10  -fa 'Monospace' -fs 12 -e ./attackRcvD.py -d`;
    }
    else
    {
        my $pid3 = fork();
        if(!$pid3)
        {
            chdir '../ASG';
            sleep 2*SLEEP_TIME;
            `xterm -title 'ASG' -hold -geometry 80x20+10+500  -fa 'Monospace' -fs 12 -e "./ASG.py -d -s -p asg-joined.properties 2>&1 | tee /tmp/asg.log"`;
        }
        else
        {
            my $pid4 = fork();
            if(!$pid4)
            {
                chdir '../../taxii-communications';
                sleep 3*SLEEP_TIME;

                `xterm -title 'Rule Xmit' -hold -geometry 80x20+900+500 -fa 'Monospace' -fs 12 -e ./ruleXmitD.py -d`;
            }
            else
            {
                my $pid5 = fork();
                if(!$pid5)
                {
                    chdir '../../taxii-communications';
                    sleep 4*SLEEP_TIME;
                    `xterm -title 'Rule Rcv' -hold -geometry 80x20+10+1400 -fa 'Monospace' -fs 12 -e ./ruleRcvD.py -d`;

                }
                else
                {
                    chdir '../../taxii-communications';
                    sleep 5*SLEEP_TIME;
                    `xterm -title 'Rule Inject' -hold -geometry 80x20+900+1400 -fa 'Monospace' -fs 12 -e ./RuleInjector.py -d`;

                }
            }
        }
    }
}

sleep 120;
#my $t1 = X11::Terminal::XTerm->new(geometery => '80x31+10+10');
#my $t2 = X11::Terminal::XTerm->new(geometery => '80x31+10+10');
