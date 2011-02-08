package Digest::PBKDF2;

use strict;
use warnings;
use parent "Digest::base";
use Crypt::PBKDF2;
use 5.010;
use Devel::Dwarn;

#ABSTRACT: This module is a subclass of Digest using the Crypt::PBKDF2 algorithm.

sub new {
    my ( $class, %params ) = @_;
    my $guts = Crypt::PBKDF2->new(
        map { $_ => $params{$_} }
            grep { defined $params{$_} }
            qw/hash_class hash_args hasher iterations output_len salt_len/
    );
    return bless { guts => $guts }, $class;
}

sub clone {
    my $self = shift;
    my $clone = {
        guts => Crypt::PBKDF2->new(
            map { $_ => $self->{guts}->{$_} } keys %{ $self->{guts} }
        ),
        _data => $self->{_data},
    };
    return bless $clone, ref $self;
}

sub add {
    my $self = shift;
    $self->{_data} .= join '', @_ if @_;
    $self;
}

sub digest {
    my $self = shift;
    my @string = split '', $self->{_data};

    my $salt = join( '', splice( @string, 0, $self->{guts}{salt_len} ) );
    my $data = join( '', @string );

    return $self->{guts}->generate( $data, salt => $salt );
}

1;
