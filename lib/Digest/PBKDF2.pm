package Digest::PBKDF2;

use strict;
use warnings;
use parent "Digest::base";
use Crypt::PBKDF2 0.101170;

#ABSTRACT: This module is a subclass of Digest using the Crypt::PBKDF2 algorithm.

sub new {
    my ( $class, %params ) = @_;
    return bless { _entries => [], _data => undef, }, $class;
}

sub clone {
    my $self  = shift;
    my $clone = {
        _data    => $self->{_data},
        _entries => $self->{_entries},
    };
    return bless $clone, ref $self;
}

sub add {
    my $self = shift;
    if (@_) {
        push @{ $self->{_entries} }, join '', @_;
        $self->{_data} .= join '', @_;
    }
    $self;
}

sub reset {
    my $self = shift;
    delete $self->{_data};
    delete $self->{_entries};
    $self;
}

sub digest {
    my $self = shift;
    my @string = split '', $self->{_data};

    my $salt;

    $salt = join( '', splice( @string, 0, length( $self->{_entries}->[0] ) ) )
        if @{ $self->{_entries} } > 1;
    my $data = join( '', @string );

    my $crypt = Crypt::PBKDF2->new( salt_len => length($salt||'') );
    my $return = $crypt->generate( $data, salt => $salt );
    $self->reset;
    $return;
}

1;

__END__

=head1 NAME

Digest::PBKDF2
A minimalist Digest module using the PBKDF2 algorithm.

=head1 NOTICE

You can only use one salt, a pre-salt, with this module. It is not smart enough
to do post-salts.

=head1 SYNOPSIS

    my $digest = Digest::PBKDF2->new;
    $digest->add('mysalt');             # salt = 'mysalt'
    $digest->add('k3wLP@$$w0rd');       # password = 'k3wLP@$$w0rd'

    $digest->add('eX+ens10n');          # password = 'k3wLP@$$w0rdeX+ens10n'

    my $result = $digest->digest;       # $PBKDF2$HMACSHA1:1000:bXlzYWx0$4P9pwp
                                        # LoF+eq5jwUbMw05qRQyZs=

That's about it.

=head1 METHODS

=over

=item new

Create a new Digest::PBKDF2 object.

=item clone

Copies the data and state from the original Digest::PBKDF2 object,
and returns a new object.

=item add

Pass this method your salt and data chunks. They are stored up
until you call digest.

=item digest

This encrypts your data and returns the encrypted string.

=item reset

After calling digest, the module calls reset on its self,
clearing data and the record of how many additions were made to the data
to be digested.

=back

=head1 SEE ALSO

L<Crypt::PBKDF2>
L<Digest>

=head1 AUTHOR

Amiri Barksdale, E<lt>abarksdale@campusexplorer.comE<gt>

=head1 COPYRIGHT

Copyright (c) 2011 by Campus Explorer, Inc.

L<http://www.campusexplorer.com>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.
