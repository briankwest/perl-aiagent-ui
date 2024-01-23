package MyTieConfig;

use strict;
use warnings;
use DBI;

sub TIEHASH {
    my ($class, %params) = @_;
    my $dbh = DBI->connect("dbi:Pg:dbname=$params{dbname};host=$params{host};port=$params{port}",
			   $params{user}, $params{password}, { RaiseError => 1, AutoCommit => 1 });
    return bless { dbh => $dbh, table => $params{table}, agent_id => $params{agent_id} }, $class;
}

sub FETCH {
    my ($self, $var) = @_;
    my $sth = $self->{dbh}->prepare("SELECT val FROM $self->{table} WHERE agent_id = ? AND var = ?");
    $sth->execute($self->{agent_id}, $var);
    my $row = $sth->fetchrow_arrayref;
    return $row ? $row->[0] : undef;
}

sub STORE {
    my ($self, $var, $val) = @_;
    $self->{dbh}->do("INSERT INTO $self->{table} (agent_id, var, val) VALUES (?, ?, ?) ON CONFLICT (agent_id, var) DO UPDATE SET val = EXCLUDED.val", undef, $self->{agent_id}, $var, $val);
}

sub DELETE {
    my ($self, $var) = @_;
    $self->{dbh}->do("DELETE FROM $self->{table} WHERE agent_id = ? AND var = ?", undef, $self->{agent_id}, $var);
}

sub EXISTS {
    my ($self, $var) = @_;
    my $sth = $self->{dbh}->prepare("SELECT 1 FROM $self->{table} WHERE agent_id = ? AND var = ?");
    $sth->execute($self->{agent_id}, $var);
    return $sth->fetchrow_arrayref ? 1 : 0;
}

sub CLEAR {
    my $self = shift;
    $self->{dbh}->do("DELETE FROM $self->{table} WHERE agent_id = ?", undef, $self->{agent_id});
}

sub FIRSTKEY {
    my $self = shift;
    $self->{iter} = $self->{dbh}->prepare("SELECT var FROM $self->{table} WHERE agent_id = ?");
    $self->{iter}->execute($self->{agent_id});
    my $row = $self->{iter}->fetchrow_arrayref;
    return $row ? $row->[0] : undef;
}

sub NEXTKEY {
    my $self = shift;
    my $row = $self->{iter}->fetchrow_arrayref;
    return $row ? $row->[0] : undef;
}

sub DESTROY {
    my $self = shift;
    $self->{dbh}->disconnect;
}

1;  # End of MyTiePg package
