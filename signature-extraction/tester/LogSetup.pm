package LogSetup;

use v5.10;

use Config::Properties;
use Log::Handler;
use Cwd;

use Class::MethodMaker
[
 scalar => [qw( properties logger
             )],
 new => [qw( -init new)]
];

=head1 NAME

LogSetup

=head1 SYNOPSIS

Sets up reasonable settings for the logging package based on entries in a
properties file.

=head1 DESCRIPTION

Extract logile, log level, and flag to log to screen from properties object.
Set up and store log handler.

=head1 METHODS

=over 2

=item init

=over 2

=item Method

Initializes values.

=item Parameters

=over 2

=item properties

A reference to a properties object which has been
initilized from a properties file.

=item log_file

Default log file name if not overriden by entry in properties file.

=back

=back

=cut

sub init
  {
    my($self,$properties,$log_file) = @_;
    $self->properties($properties);
    $self->logger($self->logSetup($properties,$log_file));
  }

=item logSetup

=over 2

=item Method

Does the actual work of initializing the Log::Handler object.

=item Parameters

=over 2

=item properties

A reference to a properties object which has been
initilized from a properties file.

=back

=item Returns

A reference to a Log::Handler object appropriately initialized.

=back

=cut

sub logSetup
{
  my($self,$properties,$log_file) = @_;

  # Set up logging
  my $log_file = $properties->getProperty("LogSetup.logfile",$log_file);
  my $log_minlevel = $properties->getProperty("LogSetup.log_minlevel",
                                              "emergency");
  my $log_maxlevel = $properties->getProperty("LogSetup.log_maxlevel",
                                              "debug");
  my $log_to_screen = $properties->getProperty("LogSetup.log_to_screen",
                                               "False");
  my $log_to_screen_flag = ($log_to_screen eq "True");

  my $log;
  if($log_to_screen_flag)
    {
      $log = Log::Handler->new(
                               file =>
                               {
                                filename => $log_file,
                                maxlevel => $log_maxlevel,
                                minlevel => $log_minlevel,
                                message_layout => "[%L:%T:%C] %m",
                                autoflush => 1,
                                die_on_errors => 0
                               },
                               screen =>
                               {
                                log_to => "STDOUT",
                                maxlevel => $log_maxlevel,
                                minlevel => $log_minlevel,
                                message_layout => "[%L:%T:%C] %m",
                                #autoflush => 1,
                                die_on_errors => 0
                               },

                              );
    }
  else
    {
      $log = Log::Handler->new(
                               file =>
                               {
                                filename => $log_file,
                                maxlevel => $log_maxlevel,
                                minlevel => $log_minlevel,
                                message_layout => "[%L:%T:%C] %m"
                               }
                              );
    }
  $log->info("Logging Starts");

  return $log;
}

1
