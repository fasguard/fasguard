package EnvProperties;

use v5.10;

use Config::Properties;
use Log::Handler;

use Class::MethodMaker
[
 scalar => [qw( properties
             )],
 new => [qw( -init new)]
];

=head1 NAME

EnvProperties

=head1 SYNOPSIS

This is a wrapper for Config::Properties that provides expansion of
environmental variables embedded in property values.

=head1 DESCRIPTION

The property is looked up using the Config::Properties package.  The value
is then evaluated inside the expression `echo $val` where we are using
backquotes.  The string returned by the echo is then provided as the value
of the getProperty method.

=head1 METHODS

=over 2

=item init

=over 2

=item Method

Initializes values.

=item Parameters

=over 2

=item properties_file

The name of the properties file.

=back

=back

=cut

sub init
  {
    my($self,$properties_file) = @_;

    my $prop_fh;
    open $prop_fh,'<',$properties_file
      or die "Unable to open $properties_file: $!";
    my $properties = Config::Properties->new();
    $properties->load($prop_fh);

    $self->properties($properties);

  }

=item getProperty

=over 2

=item Method

Passes parameters to Config::Properties and then uses backticks with echo
to expand environmental variables.

=item Parameters

=over 2

=item key

The string representing the key to lookup.

=item default

The default value to use if the key is not found.

=back

=back

=cut

sub getProperty
    {
      my($self,$key,$default) = @_;
      my $properties = $self->properties();
      #say "Key: $key";
      #say "Default: $default";
      my $val;
      if(defined $default)
        {
          $val = $properties->getProperty($key,$default);
        }
      else
        {
          say "Default not defined";
          $val = $properties->getProperty($key);
        }
      #say "Val=$val";
      if(defined $val)
        {
          if($val =~ /\$/)
            {
              #say "Val defined";
              my $expanded_val = `echo $val`;
              chomp $expanded_val;
              #say "Expanded Val:  $expanded_val";
              return $expanded_val;
            }
          else
            {
              return $val;
            }
        }
      else
        {
          return undef;
        }
    }
1
