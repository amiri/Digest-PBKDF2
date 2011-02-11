package Digest::PBKDF2;

use strict;
use warnings;
use parent "Digest::base";
use Crypt::PBKDF2;

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
