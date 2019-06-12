# firewall
[![Build Status](https://travis-ci.com/ihac/firewall.svg?branch=master)](https://travis-ci.com/ihac/firewall)

*firewall* is a CoreDNS plugin which performs as a firewall and prevents unauthorized access to protected servers.

With `firewall` enabled, users are able to define ACLs  for any DNS queries, i.e. allowing authorized queries to recurse or blocking unauthorized queries towards protected DNS zones.

This plugin can be used multiple times per Server Block.

## Syntax

```
firewall [ZONES…] {
    ACTION type QTYPE from SOURCE
    ...
}
```

- **ZONES** zones it should be authoritative for. If empty, the zones from the configuration block are used.
- **ACTION** (*allow* or *block*) defines the way of dealing with DNS queries matched by this rule. The default action is *allow*, which means a DNS query not matched by any rules will be allowed to recurse.
- **QTYPE** is the query type to match for the requests to be allowed or blocked. Common resource record types are supported. *ANY* stands for all kinds of DNS queries.
- **SOURCE** is the source ip to match for the requests to be allowed or blocked. A typical CIDR notation is supported. *ANY* stands for all possible source IP address.

## Examples

To demonstrate the use of plugin firewall, we provide some typical examples.

[Blacklist] Block all DNS queries with record type A from 192.168.0.0/16：
```
. {
    firewall {
        block type A from 192.168.0.0/16
    }
}
```

[Blacklist] Block all DNS queries from 192.168.0.0/16:

```
. {
    firewall {
        block type ANY from 192.168.0.0/16
    }
}
```

[Blacklist] Block all DNS queries with type A from any sources:

```
. {
    firewall {
        block type A from ANY
    }
}
```

[Blacklist] Block all DNS queries from 192.168.0.0/16 except 192.168.1.0/24:

```
. {
    firewall {
        allow type ANY from 192.168.1.0/24
        block type ANY from 192.168.0.0/16
    }
}
```

[Whitelist] Only allow DNS queries from 192.168.0.0/16:

```
. {
    firewall {
        allow type ANY from 192.168.0.0/16
        block type ANY from ANY
    }
}
```

[Fine-Grained] Block all DNS queries from 192.168.1.0/24 towards a.example.org:

```
example.org {
    firewall a.example.org {
        block type ANY from 192.168.1.0/24
    }
}
```

[Fine-Grained] Block all DNS queries from 192.168.1.0/24 towards a.example.org, and block all DNS queries from 192.168.2.0/24 towards b.example.org:

```
example.org {
    firewall a.example.org {
        block type ANY from 192.168.1.0/24
    }
    firewall b.example.org {
        block type ANY from 192.168.2.0/24
    }
}
```


